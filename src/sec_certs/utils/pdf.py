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

from sec_certs import constants
from sec_certs.constants import (
    GARBAGE_ALPHA_CHARS_THRESHOLD,
    GARBAGE_AVG_LLEN_THRESHOLD,
    GARBAGE_EVERY_SECOND_CHAR_THRESHOLD,
    GARBAGE_LINES_THRESHOLD,
    GARBAGE_SIZE_THRESHOLD,
)

logger = logging.getLogger(__name__)
logging.getLogger("pypdf").setLevel(logging.ERROR)


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


def convert_pdf_file(pdf_path: Path, txt_path: Path) -> tuple[bool, bool]:
    """
    Convert a PDF tile to text and save it on the `txt_path`.

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
