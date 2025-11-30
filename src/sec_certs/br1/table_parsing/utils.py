from dataclasses import asdict, fields, is_dataclass
import json
from pathlib import Path
import logging
from .model.table import BR1Table
from .model.br1_tables import BR1TablesClass
from sec_certs.br1.config.constants import INDENT

logger = logging.getLogger(__name__)


def table_asdict(table: BR1Table):
    """Exports the Table to a dictionary with required keys."""
    entries_list = [asdict(entry) for entry in table.entries]
    return {
        "section": table.section,
        "subsection": table.subsection,
        "found": table.found,
        "entries": entries_list,
    }


def br1tables_asdict(br1tables: BR1TablesClass):
    res = {}
    for f in fields(br1tables):
        table = getattr(br1tables, f.name)
        res[f.name] = table_asdict(table)
    return res


def export_br1_tables_to_json(data: BR1TablesClass, file: Path, output_dir: Path):
    output_path = output_dir / f"{file.stem}.json"
    logger.info(f"Exporting file to {output_path}")
    if not is_dataclass(data):
        raise TypeError("Expected a dataclass instance (e.g., BR1TablesClass)")
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(br1tables_asdict(data), f, indent=INDENT)
