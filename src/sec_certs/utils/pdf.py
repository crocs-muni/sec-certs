from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timedelta, timezone
from functools import reduce
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pdftotext
import pikepdf
import pytesseract
from PIL import Image

from langchain.document_loaders import PyPDFLoader
from wtpsplit import SaT
import os
import torch

from enum import Enum

from google import genai
from google.genai import types
import pathlib
import httpx

from sec_certs.constants import (
    GARBAGE_ALPHA_CHARS_THRESHOLD,
    GARBAGE_AVG_LLEN_THRESHOLD,
    GARBAGE_EVERY_SECOND_CHAR_THRESHOLD,
    GARBAGE_LINES_THRESHOLD,
    GARBAGE_SIZE_THRESHOLD,
)

from docling.document_converter import DocumentConverter
from dotenv import load_dotenv

load_dotenv()


logger = logging.getLogger(__name__)
logging.getLogger("pypdf").setLevel(logging.ERROR)

class PDFConversionMethod(Enum):
    PDFTOTEXT = 1,
    VLM = 2,
    SEGMENTATION_TRANSFORMER = 3,
    DOCLING = 4

def repair_pdf(file: Path) -> None:
    """
    Some pdfs can't be opened by PyPDF2 - opening them with pikepdf and then saving them fixes this issue.
    By opening this file in a pdf reader, we can already extract number of pages.

    :param file: file name
    :return: number of pages in pdf file
    """
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)


def ocr_pdf_file(pdf_path: Path) -> str:
    """
    OCR a PDF file and return its text contents, uses `pdftoppm` and `tesseract`.

    :param pdf_path: The PDF file to OCR.
    :return: The text contents.
    """
    with TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        ppm = subprocess.run(
            ["pdftoppm", pdf_path, tmppath / "image"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if ppm.returncode != 0:
            raise ValueError(f"pdftoppm failed: {ppm.returncode}")

        for ppm_path in tmppath.rglob("image*.ppm"):
            base = ppm_path.with_suffix("")
            content = pytesseract.image_to_string(Image.open(ppm_path), lang="eng+deu+fra")

            if content:
                with Path(base.with_suffix(".txt")).open("w") as file:
                    file.write(content)
            else:
                raise ValueError(f"OCR failed for document {ppm_path}. Check document manually")

        contents = ""

        txt_paths = [x for x in tmppath.iterdir() if x.is_file() and "image-" in x.stem and x.suffix == ".txt"]
        txt_paths = sorted(txt_paths, key=lambda txt_path: int(txt_path.stem.split("-")[1]))

        for txt_path in txt_paths:
            with txt_path.open("r", encoding="utf-8") as f:
                contents += f.read()
    return contents

_gemini_client = None

def get_gemini_client():
    global _gemini_client
    if _gemini_client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set or empty")

        _gemini_client = genai.Client(api_key=api_key)

    return _gemini_client

GEMINI_PROMPT = (
    "Fully transcribe this certificate document. Provide outputs in text. "
    "Do not prepend them with affirmations like 'Sure!', just start transcribing immediately. "
    "When you see a table, always transcribe it into a markdown table. Do not translate anything, just transcribe the text. "
    "For page breaks, use the '<page_break>' tag. If there is a drawing or a diagram, transcribe the text inside the diagram into "
    "image tags such that the content is inside, for example: <image>transcribed image content goes here</image>."
)

def convert_pdf_gemini(pdf_path: Path, txt_path: Path) -> tuple[bool, bool]:
    """
    Convert a PDF file to text using Gemini VLM for transcription and save it on the `txt_path`.

    :param pdf_path: Path to the to-be-converted PDF file.
    :param txt_path: Path to the resulting text file.
    :return: A tuple of two results, whether OCR was done and what the complete result
            was (OK/NOK). OCR always returns False for compatibility purposes.
    """
    txt = None
    ok = False
    ocr = False

    client = get_gemini_client()

    if client is None:
        logger.error("Gemini client unavailable, skipping conversion.")
        return ocr, ok

    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=[
                types.Part.from_bytes(
                    data=pdf_path.read_bytes(),
                    mime_type='application/pdf',
                ),
                GEMINI_PROMPT
            ]
        )
        txt = response.text
    except Exception as e:
        logger.error(f"Error when converting pdf->txt: {e}")
    if txt is not None:
        ok = True
        txt_path.write_text(txt, encoding="utf-8")

    return (ocr, ok)

_docling_converter = None

def get_docling_converter():
    global _docling_converter
    if _docling_converter is None:
        _docling_converter = DocumentConverter() # TODO: more fine-grained params, GPU support
    return _docling_converter

def convert_pdf_docling(pdf_path: Path, txt_path: Path) -> tuple[bool, bool]:
    txt = None
    ok = False
    ocr = False

    try:
        converter = get_docling_converter()
        result = converter.convert(pdf_path)
        txt = result.document.export_to_markdown()
    except Exception as e:
        logger.error(f"Error when converting pdf->txt: {e}")

    if txt is not None:
        ok = True
        txt_path.write_text(txt, encoding="utf-8")
    return (ocr, ok)

_sat_model = None  # global cache

def get_sat_model():
    global _sat_model
    if _sat_model is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        _sat_model = SaT("sat-12l-sm")
        _sat_model.half().to(device)
    return _sat_model

def convert_pdf_sat(pdf_path: Path, txt_path: Path) -> tuple[bool, bool]:
    """
    Convert a PDF file to text using a Segmentation Transformer for transcription and save it on the `txt_path`.

    :param pdf_path: Path to the to-be-converted PDF file.
    :param txt_path: Path to the resulting text file.
    :return: A tuple of two results, whether OCR was done and what the complete result
            was (OK/NOK). OCR always returns False for compatibility purposes.
    """
    txt = None
    ok = False
    ocr = False

    sat = get_sat_model()

    def preprocess_sent_segment(fulltext):
        return sat.split(fulltext.replace("\n", ""))

    try:
        loader = PyPDFLoader(pdf_path)
        documents = loader.load()
        txt = '\n'.join(preprocess_sent_segment("".join([page.page_content for page in documents])))
    except Exception as e:
        logger.error(f"Error when converting pdf->txt: {e}")

    if txt is not None:
        ok = True
        txt_path.write_text(txt, encoding="utf-8")

    return (ocr, ok)

def convert_pdf_pdftotext(pdf_path: Path, txt_path: Path) -> tuple[bool, bool]:
    """
    Convert a PDF file to text and save it on the `txt_path`.

    :param pdf_path: Path to the to-be-converted PDF file.
    :param txt_path: Path to the resulting text file.
    :return: A tuple of two results, whether OCR was done and what the complete result
             was (OK/NOK).
    """
    txt = None
    ok = False
    ocr = False
    try:
        with pdf_path.open("rb") as pdf_handle:
            pdf = pdftotext.PDF(pdf_handle, "", True)  # No password, Raw=True
            txt = "".join(pdf)
    except Exception as e:
        logger.error(f"Error when converting pdf->txt: {e}")

    if txt is None or text_is_garbage(txt):
        logger.warning(f"Detected garbage during conversion of {pdf_path}, attempting OCR")
        ocr = True
        try:
            txt = ocr_pdf_file(pdf_path)
            logger.info(f"OCR OK for {pdf_path}")
        except Exception as e:
            logger.error(f"Error during OCR of {pdf_path}, using garbage: {e}")

    if txt is not None:
        ok = True
        txt_path.write_text(txt, encoding="utf-8")

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


def extract_pdf_metadata(filepath: Path) -> dict[str, Any]:  # noqa: C901
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
        raise ValueError(error_msg)

    return metadata


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
    # If there is a small amount of lines that have more than one character at every second character, this is garbage.
    # This detects the ANSSI spacing issues.
    if every_second < GARBAGE_EVERY_SECOND_CHAR_THRESHOLD:
        return True
    # If there is a small ratio of alphanumeric chars to all chars, this is garbage.
    return alpha < GARBAGE_ALPHA_CHARS_THRESHOLD
