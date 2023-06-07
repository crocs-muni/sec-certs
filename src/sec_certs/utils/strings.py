from __future__ import annotations

import re
from functools import lru_cache

import spacy


@lru_cache
def load_spacy_model(spacy_model_to_load: str = "en_core_web_sm"):
    return spacy.load(spacy_model_to_load, disable=["parser", "ner"])


def fully_sanitize_string(string: str) -> str:
    return replace_special_chars_with_space(discard_trademark_symbols(string.lower())).strip()


def replace_special_chars_with_space(string: str) -> str:
    return re.sub(r"[^a-zA-Z0-9 \n\.]", " ", string)


def discard_trademark_symbols(string: str) -> str:
    return string.replace("®", "").replace("™", "")


def strip_manufacturer_and_version(string: str, manufacturers: set[str] | None, versions: set[str]) -> str:
    to_strip = versions | manufacturers if manufacturers else versions
    for x in to_strip:
        string = string.lower().replace(replace_special_chars_with_space(x.lower()), " ").strip()
    return string


def standardize_version_in_cert_name(string: str, detected_versions: set[str]) -> str:
    for ver in detected_versions:
        version_regex = r"(" + r"(\bversion)\s*" + ver + r"+) | (\bv\s*" + ver + r"+)"
        string = re.sub(version_regex, " " + ver + " ", string, flags=re.IGNORECASE)
    return string


def lemmatize_product_name(nlp, product_name: str) -> str:
    if not product_name:
        return product_name
    return " ".join([token.lemma_ for token in nlp(fully_sanitize_string(product_name))])
