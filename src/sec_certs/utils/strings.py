from __future__ import annotations

import importlib
import logging
import re
import shutil
import subprocess
import sys
from functools import lru_cache

import spacy

logger = logging.getLogger(__name__)


@lru_cache
def load_spacy_model(spacy_model_to_load: str = "en_core_web_sm", disable: tuple[str, ...] = ("parser", "ner")):
    try:
        return spacy.load(spacy_model_to_load, disable=list(disable))
    except OSError:
        logger.info(f"spaCy model {spacy_model_to_load} is missing, installing it.")
        _install_spacy_model(spacy_model_to_load)
        importlib.invalidate_caches()
        return spacy.load(spacy_model_to_load, disable=list(disable))


def _install_spacy_model(model: str) -> None:
    """Install a spaCy model into the running environment, preferring uv over pip."""
    from spacy import about
    from spacy.cli.download import get_compatibility, get_model_filename, get_version

    url = f"{about.__download_url__}/{get_model_filename(model, get_version(model, get_compatibility()))}"

    commands = []
    if uv := shutil.which("uv"):
        commands.append([uv, "pip", "install", "--python", sys.executable, url])
    commands.append([sys.executable, "-m", "pip", "install", url])

    for command in commands:
        if subprocess.run(command, check=False).returncode == 0:
            return
        logger.warning(f"Failed to install {model} with {command[0]}, trying the next installer.")

    raise RuntimeError(f"Could not install the spaCy model {model}, install it manually with `spacy download {model}`.")


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


def normalize_whitespace(text: str) -> str:
    text = text.strip()
    text = re.sub(r"[^\S\n]+", " ", text)
    text = re.sub(r"\n+", "\n", text)
    return text
