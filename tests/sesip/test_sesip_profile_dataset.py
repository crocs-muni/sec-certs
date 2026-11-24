"""tests of the SESIP profile catalog as an auxiliary dataset"""

import json
from typing import Any

import pytest

from sec_certs.configuration import config
from sec_certs.dataset import sesip_profile
from sec_certs.dataset.auxiliary_dataset_handling import ProcessingMode, SESIPProfileDatasetHandler
from sec_certs.dataset.sesip_profile import SESIPProfileDataset

BUNDLED = SESIPProfileDataset.from_bundled()
PAGES = {"gp": "SESIP Profile for Smart Locks v1.0 GPT_SPE_160 <https://globalplatform.org/locks/>", "psa": "PSA"}
NEW: dict[str, Any] = {
    "family": "Smart Locks",
    "pattern": r"Smart\s*Locks",
    "issuer": "GlobalPlatform",
    "doc_ids": ["GPT_SPE_160"],
    "url": "https://globalplatform.org/locks/",
    "psa_level": None,
    "psa_scope": None,
    "quote": "SESIP Profile for Smart Locks v1.0",
}


@pytest.fixture
def handler(tmp_path, monkeypatch):
    monkeypatch.setattr(SESIPProfileDataset, "download_page_texts", staticmethod(lambda: PAGES))
    return SESIPProfileDatasetHandler(tmp_path)


def test_saved_catalog_merges_with_the_bundled_one(handler):
    saved = SESIPProfileDataset.from_bundled(handler.dset_path)
    saved.profiles["ECN"] = {**saved["ECN"], "pattern": "stale", "doc_ids": ["GPT_SPE_152", "GPT_SPE_160"]}
    saved.profiles["Smart Locks"] = NEW
    saved.page_hashes = {"gp": "a", "psa": "b"}
    saved.to_json()
    handler.process_dataset(ProcessingMode.LOAD)
    assert handler.dset["ECN"]["pattern"] == BUNDLED["ECN"]["pattern"], "a fix in sec-certs wins"
    assert handler.dset["ECN"]["doc_ids"] == ["GPT_SPE_152", "GPT_SPE_160"], "an ID from the LLM stays"
    assert "Smart Locks" in handler.dset and handler.dset.page_hashes == {"gp": "a", "psa": "b"}
    handler.process_dataset(ProcessingMode.REBUILD)
    assert handler.dset.profiles == BUNDLED.profiles


def test_llm_writes_only_what_passes_the_checks(handler, monkeypatch):
    invented = {**NEW, "family": "Smart Doors", "pattern": "Smart\\s*Doors", "doc_ids": ["GPT_SPE_999"]}
    too_broad = {**NEW, "family": "Smart Cars", "pattern": "SESIP"}
    answer = {"updates": None, "new_profiles": [NEW, invented, too_broad, "not a dict"]}
    calls = []
    monkeypatch.setattr(sesip_profile, "_ask_llm", lambda messages: calls.append(1) or json.dumps(answer))
    monkeypatch.setattr(config, "llm_api_key", "key")
    handler.process_dataset(ProcessingMode.UPDATE)
    assert set(handler.dset.profiles) - set(BUNDLED.profiles) == {"Smart Locks"}
    assert "quote" not in handler.dset["Smart Locks"] and handler.dset.page_hashes
    handler.process_dataset(ProcessingMode.UPDATE)
    assert len(calls) == 1, "the same pages are not asked about again"


@pytest.mark.parametrize("key, warning", [(None, "pages changed"), ("key", "could not update")])
def test_no_key_or_a_failed_llm_keeps_the_catalog(handler, monkeypatch, caplog, key, warning):
    def no_answer(messages):
        raise TimeoutError("no answer")

    monkeypatch.setattr(sesip_profile, "_ask_llm", no_answer)
    monkeypatch.setattr(config, "llm_api_key", key)
    handler.process_dataset(ProcessingMode.UPDATE)
    assert warning in caplog.text
    assert handler.dset.profiles == BUNDLED.profiles and handler.dset.page_hashes is None
