import json
import logging
from dataclasses import is_dataclass
from pathlib import Path

from sec_certs.heuristics.br1.config.constants import INDENT

from .model.br1_tables import BR1Tables
from .model.table import BR1Table

logger = logging.getLogger(__name__)


def table_asdict(table: BR1Table):
    """Exports the Table to a dictionary with required keys."""
    return table.to_dict()


def br1tables_asdict(br1tables: BR1Tables):
    return br1tables.to_dict()


def export_br1_tables_to_json(data: BR1Tables, file: Path, output_dir: Path):
    output_path = output_dir / f"{file.stem}.json"
    logger.info(f"Exporting file to {output_path}")
    if not is_dataclass(data):
        raise TypeError("Expected a dataclass instance (e.g., BR1Tables)")
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(br1tables_asdict(data), f, indent=INDENT)
