import logging
from pathlib import Path

import pdftotext

from sec_certs.converter import PDFConverter
from sec_certs.utils.pdf import ocr_pdf_file, text_is_garbage

logger = logging.getLogger(__name__)


class PdftotextConverter(PDFConverter):
    HAS_JSON_OUTPUT = False

    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path | None = None) -> bool:
        """
        Convert a PDF file and save the resulst as a text file to `txt_path`.

        :param pdf_path: Path to the to-be-converted PDF file.
        :param txt_path: Path to the resulting text file.
        :param json_path: Not used by this converter.
        :return: A boolean if the conversion was successful.
        """

        txt = None
        try:
            with pdf_path.open("rb") as pdf_handle:
                pdf = pdftotext.PDF(pdf_handle, "", True)  # No password, Raw=True
                txt = "".join(pdf)
        except Exception as e:
            logger.error(f"Conversion failed for {pdf_path}: {e}")

        if txt is None or text_is_garbage(txt):
            if txt is not None:
                logger.warning(f"Detected garbage during conversion of {pdf_path}")
            try:
                txt = ocr_pdf_file(pdf_path)
                logger.info(f"OCR OK for {pdf_path}")
            except Exception as e:
                logger.error(f"OCR failed for {pdf_path}: {e}")

        if txt is not None:
            with txt_path.open("w", encoding="utf-8") as txt_handle:
                txt_handle.write(txt)
            return True

        return False
