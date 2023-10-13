import os
from typing import Dict, Optional, Any
from pathlib import Path
import abc
import os
import pytesseract

from tempfile import TemporaryDirectory
import subprocess

import logging
from PIL import Image
from io import BytesIO
import fitz

INVALID_PYMUPDF_CHARACTER = chr(0xFFFD)

class OCREngineBase(abc.ABC):
    """Abstract base class for all OCR engines."""
    
    @abc.abstractmethod
    def extract_text(self, image):
        """Extract text from the given image path using the OCR engine."""
        pass

class TesseractOCREngine(OCREngineBase):
    """
    Implementation of the OCR engine using Tesseract.
    
    Args:
        lang (str): Languages to be used by Tesseract for OCR.
        tesseract_cmd (str): Path to the Tesseract command.
    """
    
    def __init__(self, lang: str="eng+deu+fr", tesseract_cmd: str="/var/tmp/xmacko1/master_thesis/code/tesseract/AppRun") -> None:
        self._lang = lang
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    def extract_text(self, image) -> str:
        """Extract text from the given image using Tesseract."""
        return pytesseract.image_to_string(image, lang=self._lang)

class EasyOCROCREngine(OCREngineBase):
    pass

class PaddleOCREngine(OCREngineBase):
    pass

class TrOCREngine(OCREngineBase):
    pass

def build_ocr_engine(engine_choice: str, engine_kwargs: Dict[str, str]={}) -> OCREngineBase:
    """
    Factory method to build and return an instance of the desired OCR engine.
    
    Args:
        engine_choice (str): Name of the desired OCR engine.
        engine_kwargs (dict): Additional arguments for the OCR engine.
        
    Returns:
        An instance of the chosen OCR engine.
    """
    
    if engine_choice == "TesseractOCR":
        os.environ["OMP_THREAD_LIMIT"] = "1" # to not parallelize inside one tesseract process
        return TesseractOCREngine(**engine_kwargs)
    if engine_choice == "PaddleOCR":
        raise Exception("OCR NOT IMPLEMENTED")
    if engine_choice == "EasyOCR":
        raise Exception("OCR NOT IMPLEMENTED")
    if engine_choice == "TrOCR":
        raise Exception("OCR NOT IMPLEMENTED")
    raise Exception("Unknown OCR Engine")

def ocr_segment(page, old_text: Optional[str], bbox, ocr_engine: OCREngineBase) -> str:
    """
    Perform OCR on a particular segment of a page.
    
    Args:
        page: The PDF page containing the segment.
        old_text (str): The previous text from the segment.
        bbox: Bounding box of the segment.
        ocr_engine: The OCR engine to use.
        
    Returns:
        The extracted text from the segment.
    """
    logging.debug("Performing OCR on a segment of the page.")
    pix = page.get_pixmap(
        colorspace=fitz.csGRAY,  # we need no color
        matrix=fitz.Matrix(5, 5),
        clip=bbox,
    )
    if old_text is None:
        old_text = ""
    image_data = pix.tobytes("png")
    image = Image.open(BytesIO(image_data))
    new_text = ocr_engine.extract_text(image)
    left_spaces = " " * (len(old_text) - len(old_text.lstrip()))
    right_spaces = " " * (len(old_text) - len(old_text.rstrip()))
    
    return left_spaces + new_text + right_spaces
    

def ocr_segments_with_garbage_text(page: fitz.Page, page_content: Dict[str, Any], ocr_engine: OCREngineBase) -> None:
    """
    Perform OCR on segments of a page that have text which couldn't be read properly.
    
    Args:
        page: The PDF page.
        page_content (dict): The content extracted from the page.
        ocr_engine: The OCR engine to use.
    """
    ocr_count = 0
    for block in page_content["blocks"]:
        if block["type"] == "figure":
            continue
        if block["type"] == "text":
            for line in block["lines"]:
                for span in line["spans"]:
                    text, bbox = span["text"], span["bbox"]
                    if text is None or INVALID_PYMUPDF_CHARACTER in text:
                        span["text"] = ocr_segment(page, text, bbox, ocr_engine)
                        span["ocr"] = True
                        ocr_count += 1
        elif block["type"] == "table":
            for row in block["rows"]: # we also need to iterate over header
                text_cells = row["text"]
                bbox_cells = row["cells"]
                if len(text_cells) > len(bbox_cells):
                    logging.warning(f"Skipping OCR correction. There is more text cells ({len(text_cells)}) than bbox cells ({len(bbox_cells)}).")
                    continue
                if len(text_cells) < len(bbox_cells):
                    logging.warning(f"There is less text cells ({len(text_cells)}) than bbox cells ({len(bbox_cells)}).")
                    text_cells.extend([None] * len(bbox_cells) - len(text_cells))
                for i in range(len(bbox_cells)):
                    text, bbox = text_cells[i], bbox_cells[i]
                    if text is None or INVALID_PYMUPDF_CHARACTER in text:
                        text_cells[i] = ocr_segment(page, text, bbox, ocr_engine)
                        row["ocr"] = True
                        ocr_count += 1
                
    return ocr_count

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
        for ppm_path in map(Path, glob.glob(str(tmppath / "image*.ppm"))):
            base = ppm_path.with_suffix("")
            tes = subprocess.run(
                ["tesseract", "-l", "eng+deu+fra", ppm_path, base], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if tes.returncode != 0:
                raise ValueError(f"tesseract failed: {tes.returncode}")

        contents = ""

        txt_paths = [x for x in tmppath.iterdir() if x.is_file() and "image-" in x.stem and x.suffix == ".txt"]
        txt_paths = sorted(txt_paths, key=lambda txt_path: int(txt_path.stem.split("-")[1]))

        for txt_path in txt_paths:
            with txt_path.open("r", encoding="utf-8") as f:
                contents += f.read()
    return contents