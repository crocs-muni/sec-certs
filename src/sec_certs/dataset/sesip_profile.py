from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, ClassVar

import requests
from bs4 import BeautifulSoup

from sec_certs.constants import SESIP_PROFILES_GP_URL, SESIP_PROFILES_PSA_URL
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.serialization.json import ComplexSerializableType


class SESIPProfileDataset(JSONPathDataset, ComplexSerializableType):
    """SESIP profile families - name pattern, issuer, documents and PSA level"""

    BUNDLED_PATH: ClassVar[Path] = Path(__file__).parent.parent / "sesip_profiles.json"

    def __init__(self, profiles: dict[str, dict[str, Any]], json_path: str | Path | None = None):
        super().__init__(json_path)
        self.profiles = profiles

    def __iter__(self) -> Iterator[dict[str, Any]]:
        yield from self.profiles.values()

    def __getitem__(self, family: str) -> dict[str, Any]:
        return self.profiles[family]

    def __contains__(self, family: object) -> bool:
        return family in self.profiles

    def __len__(self) -> int:
        return len(self.profiles)

    def to_dict(self) -> dict[str, Any]:
        return {"profiles": self.profiles}

    @classmethod
    def from_dict(cls, dct: Mapping) -> SESIPProfileDataset:
        return cls(dct["profiles"])

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
