import logging
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from functools import reduce

import pdftotext
import pikepdf
from PyPDF2 import PdfFileReader
from PyPDF2.generic import BooleanObject, FloatObject, NumberObject, IndirectObject

from sec_certs import constants as constants

logger = logging.getLogger(__name__)


def repair_pdf(file: Path) -> None:
    """
    Some pdfs can't be opened by PyPDF2 - opening them with pikepdf and then saving them fixes this issue.
    By opening this file in a pdf reader, we can already extract number of pages
    :param file: file name
    :return: number of pages in pdf file
    """
    pdf = pikepdf.Pdf.open(file, allow_overwriting_input=True)
    pdf.save(file)


def convert_pdf_file(pdf_path: Path, txt_path: Path) -> str:
    try:
        with pdf_path.open("rb") as pdf_handle:
            pdf = pdftotext.PDF(pdf_handle, "", True)  # No password, Raw=True
            txt = "".join(pdf)
    except Exception as e:
        logger.error(f"Error when converting pdf->txt: {e}")
        return constants.RETURNCODE_NOK

    with txt_path.open("w", encoding="utf-8") as txt_handle:
        txt_handle.write(txt)

    return constants.RETURNCODE_OK


def parse_pdf_date(dateval) -> Optional[datetime]:
    """
    Parse PDF metadata date format:

    ```
        parse_pdf_date(b"D:20110617082321-04'00'")
    ```
    into
    ```
        datetime.datetime(2011, 6, 17, 8, 23, 21, tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=72000)))
    ```
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


def extract_pdf_metadata(filepath: Path) -> Tuple[str, Optional[Dict[str, Any]]]:  # noqa: C901
    def map_metadata_value(val, nope_out=False):
        if isinstance(val, BooleanObject):
            val = val.value
        elif isinstance(val, FloatObject):
            val = float(val)
        elif isinstance(val, NumberObject):
            val = int(val)
        elif isinstance(val, IndirectObject) and not nope_out:
            # Let's make sure to nope out in case of cycles
            val = map_metadata_value(val.getObject(), nope_out=True)
        else:
            val = str(val)
        return val

    metadata: Dict[str, Any] = dict()

    try:
        metadata["pdf_file_size_bytes"] = filepath.stat().st_size
        with filepath.open("rb") as handle:
            pdf = PdfFileReader(handle, strict=False)
            metadata["pdf_is_encrypted"] = pdf.getIsEncrypted()

        # see https://stackoverflow.com/questions/26242952/pypdf-2-decrypt-not-working
        if metadata["pdf_is_encrypted"]:
            pikepdf.open(filepath, allow_overwriting_input=True).save()

        with filepath.open("rb") as handle:
            pdf = PdfFileReader(handle, strict=False)
            metadata["pdf_number_of_pages"] = pdf.getNumPages()
            pdf_document_info = pdf.getDocumentInfo()

            if pdf_document_info is None:
                raise ValueError("PDF metadata unavailable")

            for key, val in pdf_document_info.items():
                metadata[str(key)] = map_metadata_value(val)

            annots = [page.get("/Annots", []) for page in pdf.pages]
            annots = reduce(lambda x, y: x + y, annots)
            links = set()
            for a in annots:
                if isinstance(a, IndirectObject):
                    note = a.getObject()
                else:
                    note = a
                link = note.get("/A", {}).get("/URI")
                if link:
                    links.add(link)
            metadata["pdf_hyperlinks"] = links

    except Exception as e:
        relative_filepath = "/".join(str(filepath).split("/")[-4:])
        error_msg = f"Failed to read metadata of {relative_filepath}, error: {e}"
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, metadata