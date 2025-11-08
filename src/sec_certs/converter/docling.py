import logging
from pathlib import Path

from docling.datamodel.accelerator_options import AcceleratorOptions
from docling.datamodel.base_models import ConversionStatus, InputFormat
from docling.datamodel.pipeline_options import (
    EasyOcrOptions,
    PdfPipelineOptions,
    TableFormerMode,
    TableStructureOptions,
)
from docling.document_converter import DocumentConverter, PdfFormatOption
from docling.exceptions import ConversionError
from docling.pipeline.standard_pdf_pipeline import StandardPdfPipeline
from docling_core.types.doc import ContentLayer, ImageRefMode

from sec_certs.converter import PDFConverter

logger = logging.getLogger(__name__)
logging.getLogger("docling").setLevel(logging.ERROR)


class DoclingConverter(PDFConverter):
    def __init__(self):
        # StandardPdfPipeline uses parallelism between pipeline stages and models.
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
        pipeline_options = PdfPipelineOptions()
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
        pipeline_options.do_ocr = False
        pipeline_options.ocr_options = EasyOcrOptions()
        pipeline_options.do_table_structure = True
        pipeline_options.table_structure_options = TableStructureOptions(mode=TableFormerMode.FAST)

        self.doc_converter = DocumentConverter(
            format_options={
                InputFormat.PDF: PdfFormatOption(pipeline_cls=StandardPdfPipeline, pipeline_options=pipeline_options)
            }
        )

    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path | None = None) -> bool:
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
                logger.warning(f"Document {pdf_path} was partially converted")
                logger.debug("With following errors:")
                for item in conv_res.errors:
                    logger.debug(f"\t{item.error_message}")

            if json_path is not None:
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

    @classmethod
    def has_json_output(cls) -> bool:
        return True
