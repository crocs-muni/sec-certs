from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from functools import reduce
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pikepdf
import pytesseract
from docling.datamodel.accelerator_options import AcceleratorOptions
from docling.datamodel.base_models import ConversionStatus, InputFormat
from docling.datamodel.pipeline_options import OcrAutoOptions, ThreadedPdfPipelineOptions
from docling.document_converter import DocumentConverter, PdfFormatOption
from docling.exceptions import ConversionError
from docling.pipeline.threaded_standard_pdf_pipeline import ThreadedStandardPdfPipeline
from docling_core.types.doc import ContentLayer, ImageRefMode
from PIL import Image

from sec_certs.constants import (
    GARBAGE_ALPHA_CHARS_THRESHOLD,
    GARBAGE_AVG_LLEN_THRESHOLD,
    GARBAGE_EVERY_SECOND_CHAR_THRESHOLD,
    GARBAGE_LINES_THRESHOLD,
    GARBAGE_SIZE_THRESHOLD,
)

logger = logging.getLogger(__name__)
logging.getLogger("pypdf").setLevel(logging.ERROR)
logging.getLogger("docling").setLevel(logging.WARNING)


class PdfConverter(ABC):
    @abstractmethod
    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path) -> bool:
        raise NotImplementedError("Not meant to be implemented by the base class.")


class DoclingConverter(PdfConverter):
    def __init__(self):
        # ThreadedPdfPipeline uses parallelism between pipeline stages and models.
        # Each pipeline step (preprocess, ocr, layout, table, assemble) runs in its own
        # dedicated thread. Each stage processes batches of configurable size in a
        # single execution. There are queues that connect the stages.
        # Avaiable options:
        #   ocr_batch_size: int = 4
        #   layout_batch_size: int = 4
        #   table_batch_size: int = 4
        #   queue_max_size: int = 100
        #   batch_timeout_seconds: float = 2.0 (max wait for filling a batch before processing)
        #
        # AcceleratorOptions controls the internal model level parallerism for inference.
        # These options apply globally to OCR, layout and table model in the pipeline.
        # Available options:
        #   num_threads: int = 4
        #   device: str = "auto" | "cuda" | "cpu" | "mps"
        #   cuda_use_flash_attention2: bool = False
        #
        # So put together visually:
        # ┌─────────────────────────────────────────────────────┐
        # │ ThreadedPdfPipeline                                 │
        # │ ┌─────────────────────────────────────────────────┐ │
        # │ │ Stage: Preprocess (Thread 1)                    │ │
        # │ │  └── batch_size=1                               │ │
        # │ ├─────────────────────────────────────────────────┤ │
        # │ │ Stage: OCR (Thread 2)                           │ │
        # │ │  ├── Uses num_threads internally                │ │
        # │ │  └── Process ocr_batch_size per run             │ │
        # │ ├─────────────────────────────────────────────────┤ │
        # │ │ Stage: Layout (Thread 3)                        │ │
        # │ │  ├── Uses num_threads internally                │ │
        # │ │  └── Process layout_batch_size per run          │ │
        # │ ├─────────────────────────────────────────────────┤ │
        # │ │ Stage: Table (Thread 4)                         │ │
        # │ │  ├── Uses num_threads internally                │ │
        # │ │  └── Process table_batch_size per run           │ │
        # │ ├─────────────────────────────────────────────────┤ │
        # │ │ Stage: Assemble (Thread 5)                      │ │
        # │ │  └── batch_size=1                               │ │
        # │ └─────────────────────────────────────────────────┘ │
        # └─────────────────────────────────────────────────────┘
        pipeline_options = ThreadedPdfPipelineOptions()
        pipeline_options.ocr_batch_size = 4
        pipeline_options.layout_batch_size = 4
        pipeline_options.table_batch_size = 4
        pipeline_options.accelerator_options = AcceleratorOptions(device="auto", num_threads=4)

        # Aviable OCR engines are: EasyOCR, RapidOCR, Tesseract or Mac OCR. You can define one, or
        # docling chooses automatically Mac Ocr, RapidOCR or EasyOCR. With these steps:
        # 1. If on Darwin device, use Mac OCR.
        # 2. Attempt to use RapidOCR with ONNX runtime backend if available.
        # 3. If ONNX runtime is not installed, try EasyOCR.
        # 4. If EasyOCR is unavailable, fall back to RapidOCR with PyTorch backend.
        # 5. If none are avaible, it will choose none and log warning.
        pipeline_options.do_ocr = True
        pipeline_options.ocr_options = OcrAutoOptions()
        pipeline_options.do_table_structure = True

        self.doc_converter = DocumentConverter(
            format_options={
                InputFormat.PDF: PdfFormatOption(
                    pipeline_cls=ThreadedStandardPdfPipeline, pipeline_options=pipeline_options
                )
            }
        )

    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path) -> bool:
        """
        Convert a PDF file and save the result as a text file to `txt_path`
        alongisde with a serialized DoclingDocument as JSON to `json_path`.

        :param pdf_path: Path to the to-be-converted PDF file.
        :param txt_path: Path to the resulting text file.
        :param json_path: Path to the resulting JSON file.
        :return: A boolean if the conversion was successful.
        """

        try:
            conv_res = self.doc_converter.convert(pdf_path)

            if conv_res.status == ConversionStatus.PARTIAL_SUCCESS:
                logger.warning(f"Document {pdf_path} was partially converted with the following errors:")
                for item in conv_res.errors:
                    logger.warning(f"\t{item.error_message}")

            conv_res.document.save_as_json(json_path, image_mode=ImageRefMode.PLACEHOLDER)
            conv_res.document.save_as_markdown(
                txt_path,
                image_placeholder="",
                escaping_underscores=False,
                included_content_layers={ContentLayer.BODY, ContentLayer.FURNITURE},
            )
        except ConversionError as e:
            logger.error(f"Conversion failed for {pdf_path}: {e}")
            return False

        return True


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
