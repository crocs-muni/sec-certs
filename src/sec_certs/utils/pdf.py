from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from functools import reduce
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF
import pikepdf

from sec_certs import constants
from sec_certs.constants import (
    GARBAGE_ALPHA_CHARS_THRESHOLD,
    GARBAGE_AVG_LLEN_THRESHOLD,
    GARBAGE_EVERY_SECOND_CHAR_THRESHOLD,
    GARBAGE_LINES_THRESHOLD,
    GARBAGE_SIZE_THRESHOLD,
)
from sec_certs.utils.ocr import OCREngineBase, build_ocr_engine, ocr_pdf_file, ocr_segments_with_garbage_text

logger = logging.getLogger(__name__)
logging.getLogger("pypdf").setLevel(logging.ERROR)

PYMUPDF_TYPES = {
    0: "text",
    1: "figure"
}

def repair_pdf(file: Path) -> None:
    """
    Some pdfs can't be opened by PyPDF2 - opening them with pikepdf and then saving them fixes this issue.
    By opening this file in a pdf reader, we can already extract number of pages.

    :param file: file name
    :return: number of pages in pdf file
    """
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)
    
def extract_texts_and_figures(pdf_page: fitz.Page) -> dict[str, Any]:
    """
    Extract text and figures from a given PDF page.
    
    Args:
        pdf_page: The page from which to extract the content.
        
    Returns:
        A dictionary containing extracted texts and figures.
    """    
    page_dict = pdf_page.get_text("dict", sort=True)
    for block in page_dict.get("blocks", []):
        block["type"] = PYMUPDF_TYPES[block["type"]]
        if block["type"] == "figure":
            block.pop("image") # this is too big and useless in byte format
    return page_dict

def extract_tables_from_page(pdf_page: fitz.Page, logging_metadata: dict[str, str]) -> list[dict[str, Any]]:
    """
    Extract tables from a given PDF page.
    
    Args:
        pdf_page: The page from which to extract tables.
        
    Returns:
        A list of dictionaries, each representing a table.
    """
    
    if not hasattr(fitz.Page, "find_tables"):
        raise Exception("This PyMuPDF version does not support the table feature")
    
    tables = None
    try:
        tables = pdf_page.find_tables()
    except Exception as e: # can fail when table is detected but it is actually empty
        logging.error(f"Extract tables for {logging_metadata}: {e}")
        return []
    out_tables = []
    for table in tables:
        rows_text = table.extract()
        bbox = table.bbox
        rows = table.rows
        
        out_table = table.__dict__.copy()
        # remove useless
        out_table.pop("page")
        out_table.pop("cells")
        # add header while renaming strings to text
        out_table["header"] = out_table["header"].__dict__.copy()
        out_table["header"]["text"] = out_table["header"].pop("names")
        
        out_table["bbox"] = bbox
        out_table["rows"] = [
            {"text": rows_text[i], **rows[i].__dict__} 
            for i in 
            range(len(rows))
        ]
        out_table["type"] = "table"
        out_table["df"] = table.to_pandas()
        
        out_tables.append(out_table)
    
    logging.debug(f"Extracted {len(out_tables)} tables from page.")
    return out_tables

    
def extract_from_page(pdf_page: fitz.Page, extract_tables: bool, logging_metadata: dict[str, str]) -> dict[str, Any]:
    """
    Extract all relevant information (text, figures, tables) from a given PDF page.
    
    Args:
        pdf_page: The page from which to extract content.
        
    Returns:
        A dictionary containing the extracted content.
    """
    texts_and_figures = extract_texts_and_figures(pdf_page)
    if extract_tables:
        tables = extract_tables_from_page(pdf_page, logging_metadata)
        texts_and_figures["blocks"].extend(tables)
    # sort just in case
    texts_and_figures["blocks"] = sorted(
        texts_and_figures["blocks"], 
        # bbox is x0, y0, x1, y1, we sort by y1 and x0 as in PyMuPDF
        key=lambda block: (block["bbox"][3], block["bbox"][0]) 
    )
    return texts_and_figures


def segment_pdf(pdf, ocr_engine: OCREngineBase, extract_tables: bool, logging_metadata: dict[str, str]) -> list[dict[str, Any]]:
    """
    Segment a PDF into its constituent parts (texts, tables, figures).
    
    Args:
        pdf: The PDF document.
        ocr_engine: The OCR engine to use for text extraction.
        
    Returns:
        A list of dictionaries, each representing content from a page.
    """
    pages = []
    ocr_count = 0
    for i, page in enumerate(pdf):
        page_content = extract_from_page(page, extract_tables, {"page_index": str(i), **logging_metadata})
        ocr_count += ocr_segments_with_garbage_text(page, page_content, ocr_engine)
        pages.append(page_content)
    if ocr_count > 0:
        logging.debug(f"Used OCR for {logging_metadata} in {ocr_count} cases")
    return pages



def convert_pdf_file(pdf_path: Path, txt_path: Path) -> tuple[bool, bool]:
    """
    Convert a PDF tile to text and save it on the `txt_path`.

    :param pdf_path: Path to the to-be-converted PDF file.
    :param txt_path: Path to the resulting text file.
    :return: A tuple of two results, whether OCR was done and what the complete result
             was (OK/NOK).
    """

    def segmented_pdf_to_text(segmented_pdf: list[dict[str, Any]]) -> str:

        pdf_page_texts = []
        for pdf_page in segmented_pdf:
            block_texts = []
            for block in pdf_page["blocks"]:
                # skip figure
                if block["type"] == "figure":
                    continue
                # deal with text which is composed of lines composed of spans
                if block["type"] == "text":
                    lines = []
                    for line in block["lines"]:
                        spans = []
                        for span in line["spans"]:
                            spans.append(span.strip())
                        line = " ".join(spans)
                        if len(line.strip()) > 0:
                            lines.append(line)
                    block_text = "\n".join(lines) # TODO maybe change to " ", depends how we wanna view it
                    if len(block_text.strip()) > 0:
                        block_texts.append(block_text) # lines are separated by "\n"
                # deal with table which has header and rows
                elif block["type"] == "table":
                    row_texts = []
                    for row in [block["header"]] + block["rows"]: # iterate both header and rows
                        row_text = "\t".join(
                            [
                                cell_text.strip() if cell_text is not None else "" 
                                for cell_text 
                                in row["text"]
                            ]
                            )
                        row_texts.append(row_text)
                    block_texts.append("\n".join(row_texts))
                    
            pdf_page_texts.append("\n\n".join(block_texts)) # free line between blocks

        return "\n\n".join(pdf_page_texts) # create free line between pages

    txt = None
    ok = False
    ocr = False

    # TODO move these things outside the function...
    ocr_engine = build_ocr_engine("TesseractOCR")
    extract_tables = False # SET THIS TO TRUE TO EXTRACT TABLES

    # parse structure of the document
    try:
        doc = fitz.open(pdf_path)
        segmented_doc = segment_pdf(doc, ocr_engine, extract_tables, {}) # last argument is logging metadata, empty in this PoC
        doc.close()
        if not doc.is_closed:
            logging.warning("There was issue closing the doc.")
        txt = segmented_pdf_to_text(segmented_doc)
    except Exception:
        logger.error("Error when parsing pdf using PyMuPDF")
    
    # TODO this check should be revisited (changed or fully removed) as now OCR is done inside `segment_pdf`
    if txt is None or text_is_garbage(txt):
        logger.warning(f"Detected garbage during conversion of {pdf_path}")
        ocr = True
        try:
            txt = ocr_pdf_file(pdf_path)
            logger.info(f"OCR OK for {pdf_path}")
        except Exception as e:
            logger.error(f"Error during OCR of {pdf_path}, using garbage: {e}")

    if txt is not None:
        ok = True
        with txt_path.open("w", encoding="utf-8") as txt_handle:
            txt_handle.write(txt)

    return ocr, ok


def parse_pdf_date(dateval: bytes | None) -> datetime | None:
    """
    Parse PDF metadata date format:

    ```
        parse_pdf_date(b"D:20110617082321-04'00'")
    ```
    into
    ```
        datetime.datetime(2011, 6, 17, 8, 23, 21, tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=72000)))
    ```

    :param dateval: The date as in the PDF metadata.
    :return: The parsed datetime, if successful, else `None`.
    """
    if dateval is None:
        return None
    clean = dateval.decode("utf-8").replace("D:", "")
    tz = None
    tzoff = None
    if "+" in clean:
        clean, tz = clean.split("+")
        tzoff = 1
    if "-" in clean:
        clean, tz = clean.split("-")
        tzoff = -1
    elif "Z" in clean:
        clean, tz = clean.split("Z")
        tzoff = 1
    try:
        res_datetime = datetime.strptime(clean, "%Y%m%d%H%M%S")
        if tz and tzoff:
            tz_datetime = datetime.strptime(tz, "%H'%M'")
            delta = tzoff * timedelta(hours=tz_datetime.hour, minutes=tz_datetime.minute)
            res_tz = timezone(delta)
            res_datetime = res_datetime.replace(tzinfo=res_tz)
        return res_datetime
    except ValueError:
        return None


def extract_pdf_metadata(filepath: Path) -> tuple[str, dict[str, Any] | None]:  # noqa: C901
    """
    Extract PDF metadata, such as the number of pages, author, title, etc.

    :param filepath: THe path to the PDF.
    :return: A tuple of the result code (see constants) and the metadata dictionary.
    """
    from pypdf import PdfReader
    from pypdf.generic import (
        BooleanObject,
        ByteStringObject,
        FloatObject,
        IndirectObject,
        NumberObject,
        TextStringObject,
    )

    def map_metadata_value(val, nope_out=False):
        if isinstance(val, BooleanObject):
            val = val.value
        elif isinstance(val, FloatObject):
            val = float(val)
        elif isinstance(val, NumberObject):
            val = int(val)
        elif isinstance(val, IndirectObject) and not nope_out:
            # Let's make sure to nope out in case of cycles
            val = map_metadata_value(val.get_object(), nope_out=True)
        elif isinstance(val, TextStringObject):
            val = str(val)
        elif isinstance(val, ByteStringObject):
            try:
                val = val.decode("utf-8")
            except UnicodeDecodeError:
                val = str(val)
        else:
            val = str(val)
        return val

    def resolve_indirect(val, bound=10):
        if isinstance(val, list) and bound:
            return [resolve_indirect(v, bound - 1) for v in val]
        if isinstance(val, IndirectObject) and bound:
            return resolve_indirect(val.get_object(), bound - 1)
        return val

    metadata: dict[str, Any] = {}

    try:
        metadata["pdf_file_size_bytes"] = filepath.stat().st_size
        with filepath.open("rb") as handle:
            pdf = PdfReader(handle, strict=False)
            metadata["pdf_is_encrypted"] = pdf.is_encrypted

        # see https://stackoverflow.com/questions/26242952/pypdf-2-decrypt-not-working
        if metadata["pdf_is_encrypted"]:
            pikepdf.open(filepath, allow_overwriting_input=True).save()

        with filepath.open("rb") as handle:
            pdf = PdfReader(handle, strict=False)
            metadata["pdf_number_of_pages"] = len(pdf.pages)
            pdf_document_info = pdf.metadata

            if pdf_document_info is None:
                raise ValueError("PDF metadata unavailable")

            for key, val in pdf_document_info.items():
                metadata[str(key)] = map_metadata_value(val)

            # Get the hyperlinks in the PDF
            annots = [page.get("/Annots", []) for page in pdf.pages]
            annots = reduce(lambda x, y: x + y, map(resolve_indirect, annots))
            links = set()
            for annot in annots:
                try:
                    A = resolve_indirect(annot.get("/A", {}))
                    link = resolve_indirect(A.get("/URI"))
                    if link:
                        links.add(map_metadata_value(link))
                except Exception:
                    pass
            metadata["pdf_hyperlinks"] = links

    except Exception as e:
        relative_filepath = "/".join(str(filepath).split("/")[-4:])
        error_msg = f"Failed to read metadata of {relative_filepath}, error: {e}"
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, metadata


def text_is_garbage(text: str) -> bool:
    """
    Detect whether the given text is "garbage". A series of tests is applied,
    using the number of lines, average line length, total size, every second character on a line
    and the ratio of alphanumeric characters.

    :param text: The tested text.
    :return: Whether the text is a "garbage" result of pdftotext conversion.
    """
    size = len(text)
    content_len = 0
    lines = 0
    every_second = 0
    alpha_len = len("".join(filter(str.isalpha, text)))
    for line in text.splitlines():
        content_len += len(line)
        lines += 1
        if len(set(line[1::2])) > 1:
            every_second += 1

    avg_line_len = content_len / lines if lines else 0
    alpha = alpha_len / size if size else 0

    # If number of lines is small, this is garbage.
    if lines < GARBAGE_LINES_THRESHOLD:
        return True
    # If the file size is small, this is garbage.
    if size < GARBAGE_SIZE_THRESHOLD:
        return True
    # If the average length of a line is small, this is garbage.
    if avg_line_len < GARBAGE_AVG_LLEN_THRESHOLD:
        return True
    # If there a small amount of lines that have more than one character at every second character, this is garbage.
    # This detects the ANSSI spacing issues.
    if every_second < GARBAGE_EVERY_SECOND_CHAR_THRESHOLD:
        return True
    # If there is a small ratio of alphanumeric chars to all chars, this is garbage.
    if alpha < GARBAGE_ALPHA_CHARS_THRESHOLD:
        return True
    return False
