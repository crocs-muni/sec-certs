from functools import lru_cache
from typing import Any

from sec_certs.cert_rules import rules

_CRYPTO = {
    "Symmetric Algorithms": "symmetric_crypto",
    "Asymmetric Algorithms": "asymmetric_crypto",
    "Post-quantum Algorithms": "pq_crypto",
    "Hash functions": "hash_function",
    "Schemes": "crypto_scheme",
    "Protocols": "crypto_protocol",
    "Randomness": "randomness",
    "Engines": "crypto_engine",
    "Libraries": "crypto_library",
    "Elliptic Curves": "ecc_curve",
    "Block cipher modes": "cipher_mode",
    "TLS cipher suites": "tls_cipher_suite",
}

_DEVICE = {
    "Device models": "device_model",
    "JavaCard versions": "javacard_version",
    "JavaCard API constants": "javacard_api_const",
    "JavaCard packages": "javacard_packages",
    "Operating System name": "os_name",
    "CPLC": "cplc_data",
    "IC data groups": "ic_data_group",
    "Trusted Execution Environments": "tee_name",
    "Vendor": "vendor",
}

_CC = {
    "Security level": "cc_security_level",
    "Claims": "cc_claims",
    "Security Assurance Requirements (SAR)": "cc_sar",
    "Security Functional Requirements (SFR)": "cc_sfr",
    "Protection profiles": "cc_protection_profile_id",
    "Certificates": "cc_cert_id",
    "Evaluation facilities": "eval_facility",
}

_SECURITY = {
    "Side-channel analysis": "side_channel_analysis",
    "Vulnerabilities": "vulnerability",
    "Certification process": "certification_process",
}

_FIPS_SECURITY = {
    "Security level": "fips_security_level",
    **_SECURITY,
}

_OTHER = {
    "Standards": "standard_id",
    "Technical reports": "technical_report_id",
}

KEYWORD_GROUPS = {
    "crypto": _CRYPTO,
    "device": _DEVICE,
    "cc": _CC,
    "security": _SECURITY,
    "fips_security": _FIPS_SECURITY,
    "other": _OTHER,
}

CC_KEYWORD_GROUPS = {
    "Cryptography": _CRYPTO,
    "Device": _DEVICE,
    "Common Criteria": _CC,
    "Security": _SECURITY,
    "Other": _OTHER,
}

FIPS_KEYWORD_GROUPS = {
    "Cryptography": _CRYPTO,
    "Device": _DEVICE,
    "Security": _FIPS_SECURITY,
    "Other": _OTHER,
}


def _slug(name: str) -> str:
    return name.lower().replace(" ", "_")


def _build_subtree(node: dict, prefix: str) -> list[dict[str, Any]]:
    children = []
    for name, val in node.items():
        path = f"{prefix}.{name}"
        if isinstance(val, dict):
            children.append({"name": name, "path": path, "children": _build_subtree(val, path)})
        else:
            children.append({"name": name, "path": path, "children": []})
    return children


@lru_cache(maxsize=4)
def build_keyword_tree(scheme: str = "cc") -> list[dict[str, Any]]:
    groups = FIPS_KEYWORD_GROUPS if scheme == "fips" else CC_KEYWORD_GROUPS
    tree = []
    for group_name, mapping in groups.items():
        categories = []
        for display, cat in mapping.items():
            cat_rules = rules.get(cat)
            if not cat_rules:
                continue
            categories.append({"name": display, "path": cat, "children": _build_subtree(cat_rules, cat)})
        if categories:
            tree.append({"name": group_name, "path": _slug(group_name), "children": categories})
    return tree


@lru_cache(maxsize=4)
def group_paths(scheme: str = "cc") -> dict[str, list[str]]:
    groups = FIPS_KEYWORD_GROUPS if scheme == "fips" else CC_KEYWORD_GROUPS
    return {_slug(name): list(mapping.values()) for name, mapping in groups.items()}


def keyword_units(keywords: list[str] | None, scheme: str = "cc") -> list[list[str]]:
    if not keywords:
        return []
    groups = group_paths(scheme)
    return [groups.get(token, [token]) for token in keywords]
