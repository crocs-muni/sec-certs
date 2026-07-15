from urllib.parse import urljoin

import requests
from flask import current_app


def _get_headers():
    return {"Authorization": f"Bearer {current_app.config['LLM_API_KEY']}", "Content-Type": "application/json"}


def _resolve_url(url: str):
    return urljoin(current_app.config["LLM_API_URL"], url)


def post(url: str, data=None, stream=False):
    """Send a POST request to the OpenAI API."""
    response = requests.post(_resolve_url(url), headers=_get_headers(), json=data, stream=stream)
    return response
