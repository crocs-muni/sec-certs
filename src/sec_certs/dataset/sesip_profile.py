from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, ClassVar, Final

import requests
from bs4 import BeautifulSoup

from sec_certs.configuration import config
from sec_certs.constants import SESIP_PROFILES_GP_URL, SESIP_PROFILES_PSA_URL
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.serialization.json import ComplexSerializableType

_LLM_RULES: Final = """You maintain a catalog of SESIP profiles for the sec-certs library. You get the catalog \
(JSON list) and the text of two official pages: the GlobalPlatform specification library (SESIP) and \
PSA Certified certification resources. Links are written as <url> after the link text. Compare them.
Rules:
- One catalog entry = one profile family. Versions are not stored: a new version of a known profile \
is not a new profile, only report its new document ID in "updates".
- Only SESIP profiles. Ignore the methodology, FAQ, mapping documents, questionnaires and guides.
- Every "quote" is copied exactly from the page text. Document IDs and URLs must appear on the pages.
- "pattern" is a case-insensitive Python regex for the profile name as written in certificates, in \
the style of the existing patterns.
- "psa_level" is 2, 3 or 4 for PSA Certified profiles, otherwise null.
- "psa_scope" says what a PSA Certified profile evaluates, judged by its name: "psa_whole" for a whole \
PSA Root of Trust (e.g. "PSA Certified Level 3"), "ise_se_or_rot_component" for iSE/SE profiles, which \
can also be used for a RoT Component (e.g. "Level 4 iSE/SE (Includes Level 4 RoT Component)"), \
"rot_component" for RoT Component only profiles, null for profiles that are not PSA Certified.
Answer with one JSON object only:
{"unchanged": [family], "updates": [{"family", "add_doc_ids", "url", "quote"}], "new_profiles": \
[{"family", "pattern", "issuer", "doc_ids", "url", "psa_level", "psa_scope", "quote"}], \
"not_on_pages": [family], "notes": [text]}"""


class SESIPProfileDataset(JSONPathDataset, ComplexSerializableType):
    """SESIP profile families - name pattern, issuer, documents and PSA level"""

    BUNDLED_PATH: ClassVar[Path] = Path(__file__).parent.parent / "sesip_profiles.json"

    def __init__(
        self,
        profiles: dict[str, dict[str, Any]],
        page_hashes: dict[str, str] | None = None,
        json_path: str | Path | None = None,
    ):
        super().__init__(json_path)
        self.profiles = profiles
        self.page_hashes = page_hashes

    def __iter__(self) -> Iterator[dict[str, Any]]:
        yield from self.profiles.values()

    def __getitem__(self, family: str) -> dict[str, Any]:
        return self.profiles[family]

    def __contains__(self, family: object) -> bool:
        return family in self.profiles

    def __len__(self) -> int:
        return len(self.profiles)

    def to_dict(self) -> dict[str, Any]:
        return {"profiles": self.profiles, "page_hashes": self.page_hashes}

    @classmethod
    def from_dict(cls, dct: Mapping) -> SESIPProfileDataset:
        return cls(dct["profiles"], dct.get("page_hashes"))

    @classmethod
    def from_bundled(cls, json_path: str | Path | None = None) -> SESIPProfileDataset:
        """The catalog in sec-certs package"""
        profiles = json.loads(cls.BUNDLED_PATH.read_text(encoding="utf-8"))
        return cls({profile["family"]: profile for profile in profiles}, json_path=json_path)

    @staticmethod
    def download_page_texts() -> dict[str, str]:
        """text of the GP and PSA Certified pages which list SESIP profiles"""
        gp_pages = []
        for page in range(1, 20):
            html = _download(SESIP_PROFILES_GP_URL, {"committee": "667", "page": page})
            if "No Results" in html:
                break
            gp_pages.append(html)
        return {"gp": _page_text("\n".join(gp_pages)), "psa": _page_text(_download(SESIP_PROFILES_PSA_URL))}

    def ask_llm(self, texts: dict[str, str]) -> dict[str, Any]:
        """Changes of the catalog the Ai finds on the pages"""
        pages = f"GLOBALPLATFORM PAGE:\n{texts['gp']}\n\nPSA CERTIFIED PAGE:\n{texts['psa']}"
        user = f"CATALOG:\n{json.dumps(list(self), indent=1)}\n\n{pages}"
        answer = _ask_llm([{"role": "system", "content": _LLM_RULES}, {"role": "user", "content": user}])
        return json.loads(answer[answer.index("{") : answer.rindex("}") + 1])


def _download(url: str, form: dict[str, Any] | None = None) -> str:
    response = requests.request(
        "POST" if form else "GET", url, data=form, headers={"User-Agent": "Mozilla/5.0"}, timeout=60
    )
    response.raise_for_status()
    return response.text


def _page_text(html: str) -> str:
    soup = BeautifulSoup(html, "html5lib")
    for tag in soup(["script", "style", "noscript", "header", "nav", "footer"]):
        tag.decompose()
    for link in soup.find_all("a", href=True):
        if not link["href"].startswith("#"):
            link.append(f" <{link['href']}>")
    return " ".join(soup.get_text(" ").split())


def _ask_llm(messages: list[dict[str, str]]) -> str:
    with requests.post(
        f"{config.llm_api_url}/chat/completions",
        headers={"Authorization": f"Bearer {config.llm_api_key}"},
        json={"model": config.llm_model, "messages": messages, "temperature": 0, "stream": True},
        stream=True,
        timeout=(30, 600),
    ) as response:
        response.raise_for_status()
        answer, deadline = "", time.monotonic() + config.llm_timeout
        for line in response.iter_lines():
            if time.monotonic() > deadline:
                raise TimeoutError(f"No whole answer from {config.llm_model} in {config.llm_timeout} s")
            if line.startswith(b"data: {"):
                for choice in json.loads(line[6:]).get("choices", []):
                    answer += choice.get("delta", {}).get("content") or ""
    return answer


_PLAIN: Final = str.maketrans("\u2018\u2019\u2010\u2011\u2013\u2014", "''----")


def _psa_scope_by_name(item: dict[str, Any]) -> str | None:
    family = item.get("family") or ""
    if not item.get("psa_level"):
        return None
    if "iSE/SE" in family:
        return "ise_se_or_rot_component"
    return "rot_component" if "RoT Component" in family else "psa_whole"


def _llm_problems(item: dict[str, Any], pages: str) -> list[str]:
    """Ai correctness check"""
    claims = [item.get("quote"), item.get("url"), *(item.get("add_doc_ids") or []), *(item.get("doc_ids") or [])]
    problems = [f"not on the pages: {c}" for c in claims if c and str(c).translate(_PLAIN) not in pages]
    if "pattern" in item:
        try:
            re.compile(item["pattern"], re.IGNORECASE)
        except (re.error, TypeError) as e:
            problems.append(f"pattern does not compile: {e}")
        if not (
            isinstance(item.get("family"), str)
            and isinstance(item.get("doc_ids"), list)
            and item.get("psa_level") in (None, 2, 3, 4)
            and item.get("psa_scope") == _psa_scope_by_name(item)
        ):
            problems.append("bad family, doc_ids, psa_level or psa_scope")
    return problems
