from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import yaml

# This ignores ACM and AMA SARs that are present in CC version 2
SARS_IMPLIED_FROM_EAL: dict[str, set[tuple[str, int]]] = {
    "EAL1": {
        ("ADV_FSP", 1),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 1),
        ("ALC_CMS", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 1),
        ("ASE_REQ", 1),
        ("ASE_TSS", 1),
        ("ATE_IND", 1),
        ("AVA_VAN", 1),
    },
    "EAL2": {
        ("ADV_ARC", 1),
        ("ADV_TDS", 1),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 2),
        ("ALC_CMS", 2),
        ("ALC_DEL", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 1),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 2),
    },
    "EAL3": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 3),
        ("ADV_TDS", 2),
        ("AGD_PRE", 1),
        ("ALC_CMC", 3),
        ("ALC_CMS", 3),
        ("ALC_DEL", 1),
        ("ALC_DVS", 1),
        ("ALC_LCD", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 2),
        ("ATE_DPT", 1),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 2),
    },
    "EAL4": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 4),
        ("ADV_IMP", 1),
        ("ADV_TDS", 3),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 4),
        ("ALC_CMS", 4),
        ("ALC_DEL", 1),
        ("ALC_DVS", 1),
        ("ALC_LCD", 1),
        ("ALC_TAT", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 2),
        ("ATE_DPT", 1),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 3),
    },
    "EAL5": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 5),
        ("ADV_IMP", 1),
        ("ADV_INT", 2),
        ("ADV_TDS", 4),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 4),
        ("ALC_CMS", 5),
        ("ALC_DEL", 1),
        ("ALC_DVS", 1),
        ("ALC_LCD", 1),
        ("ALC_TAT", 2),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 2),
        ("ATE_DPT", 3),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 4),
    },
    "EAL6": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 5),
        ("ADV_IMP", 2),
        ("ADV_INT", 3),
        ("ADV_SPM", 1),
        ("ADV_TDS", 5),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 5),
        ("ALC_CMS", 5),
        ("ALC_DEL", 1),
        ("ALC_DVS", 2),
        ("ALC_LCD", 1),
        ("ALC_TAT", 3),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 3),
        ("ATE_DPT", 3),
        ("ATE_FUN", 2),
        ("ATE_IND", 2),
        ("AVA_VAN", 5),
    },
    "EAL7": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 6),
        ("ADV_IMP", 2),
        ("ADV_INT", 3),
        ("ADV_SPM", 1),
        ("ADV_TDS", 6),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 5),
        ("ALC_CMS", 5),
        ("ALC_DEL", 1),
        ("ALC_DVS", 2),
        ("ALC_LCD", 2),
        ("ALC_TAT", 3),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 3),
        ("ATE_DPT", 4),
        ("ATE_FUN", 2),
        ("ATE_IND", 3),
        ("AVA_VAN", 5),
    },
}

security_level_csv_scan = r"EAL[1-7]\+?"


REGEXEC_SEP = "[ ,;\\[\\]”\"')(.]"
MATCH_START = "(?P<match>"
MATCH_END = ")"
REGEXEC_SEP_START = f"(?:^|{REGEXEC_SEP})"
REGEXEC_SEP_END = f"(?:$|{REGEXEC_SEP})"


SERVICE_PACK_RE = re.compile(r"(?:sp|service pack)\s{0,1}\d{1,2}", re.IGNORECASE)
RELEASE_RE = re.compile(r"(?:r|release)\s{0,1}\d{1,2}", re.IGNORECASE)
PLATFORM_REGEXES = {
    "linux": re.compile(r"linux", re.IGNORECASE),
    "mac_os": re.compile(r"mac\s?os\s?x?", re.IGNORECASE),
    "windows": re.compile(r"windows", re.IGNORECASE),
    "android": re.compile(r"android", re.IGNORECASE),
    "ios": re.compile(r"(ios|iphone os)", re.IGNORECASE),
}

FIPS_ALGS_IN_TABLE = r"(?:#[CcAa]?\s?|(?:Cert)\.?[^. ]*?\s?)(?:[CcAa]\s)?(?P<id>\d+)"

# Marks a table in a security policy as one that plausibly lists validated algorithms.
FIPS_ALG_TABLE_HINT = re.compile(
    r"approved\s+(?:security\s+function|algorithm|cryptographic\s+function)s?"
    r"|security\s+functions?"
    r"|cryptographic\s+(?:algorithm|function)s?"
    r"|algorithms?\b"
    r"|\bcavp\b"
    r"|\bcert(?:ificate)?s?\.?\s*(?:#|nos?\.?|numbers?)"
    r"|validation\s*(?:#|nos?\.?|numbers?|cert(?:ificate)?s?)",
    re.IGNORECASE,
)

# Marks a column of a table as the one holding validation certificate numbers. Deliberately does not treat
# a column headed only "#" as one: across the security policy corpus those are row counters in operational
# environment and port tables, never certificate numbers.
FIPS_ALG_CERT_COLUMN = re.compile(
    r"\bcert(?:ificate)?s?\b|\bcavp\b|\bvalidation\b|\balgorithm\s*(?:#|nos?\.?|numbers?)",
    re.IGNORECASE,
)

# Disqualifies a column from holding validation numbers, e.g. a "Validation Date" column would otherwise
# match FIPS_ALG_CERT_COLUMN and have its dates read as certificate numbers.
FIPS_ALG_COLUMN_EXCLUDE = re.compile(
    r"\b(?:date|year|version|revision|size|length|bits?|mode|standard|strength|type|level)\b",
    re.IGNORECASE,
)

# An algorithm validation number preceded by an explicit marker, safe to look for anywhere.
FIPS_ALG_ID_MARKED = re.compile(
    r"(?:#|\bcert(?:ificate)?s?\.?\s*(?:#|nos?\.?|numbers?)?|\bcavp\b\s*(?:#|nos?\.?)?)"
    r"\s*(?P<prefix>[ACac])?\s*(?P<id>\d{1,5})\b",
    re.IGNORECASE,
)

# A CAVP validation number in its prefixed form, e.g. "A3045". Distinctive enough to be recognized among
# other text, but only inside a known certificate-number column: policies list several per cell, mixed with
# labels such as "Version 3.3: A3045, A3053, ...".
FIPS_ALG_ID_CAVP = re.compile(r"(?<![\w.#-])(?P<prefix>[ACac])(?P<id>\d{1,5})(?![\w.])")

# A bare algorithm validation number, only meaningful inside a known certificate-number column, and only
# when the cell holds nothing but numbers.
FIPS_ALG_ID_BARE = re.compile(r"(?<![\w.#])#?\s*(?P<prefix>[ACac])?\s*(?P<id>\d{1,5})(?![\w.])")

# A cell that holds nothing but validation numbers and their separators.
FIPS_ALG_ID_CELL = re.compile(r"[#ACac0-9\s,;/&.\-]+(?:\band\b[#ACac0-9\s,;/&.\-]+)*", re.IGNORECASE)


def _load():
    script_dir = Path(__file__).parent
    filepath = script_dir / "rules.yaml"
    with Path(filepath).open("r") as file:
        return yaml.load(file, Loader=yaml.FullLoader)


def _process(obj: dict | list):
    if isinstance(obj, dict):
        return {k: _process(v) for k, v in obj.items()}
    return [
        re.compile(
            REGEXEC_SEP_START + MATCH_START + rule + MATCH_END + REGEXEC_SEP_END,
            re.MULTILINE,
        )
        for rule in obj
    ]


rules = _load()

cc_rules = {}
for rule_group in rules["cc_rules"]:
    cc_rules[rule_group] = _process(rules[rule_group])

fips_rules = {}
for rule_group in rules["fips_rules"]:
    fips_rules[rule_group] = _process(rules[rule_group])


PANDAS_KEYWORDS_CATEGORIES: Final[list[str]] = [
    "symmetric_crypto",
    "asymmetric_crypto",
    "pq_crypto",
    "hash_function",
    "crypto_scheme",
    "crypto_protocol",
    "randomness",
    "cipher_mode",
    "ecc_curve",
    "crypto_engine",
    "crypto_library",
]
