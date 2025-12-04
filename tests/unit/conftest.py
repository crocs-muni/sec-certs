"""Conftest for unit tests that don't require database fixtures.

This file overrides the session-scoped autouse fixtures from the parent conftest.py
by providing empty fixtures with the same names.
"""

import pytest


@pytest.fixture(autouse=True, scope="session")
def mongo_data():
    """Override the mongo_data fixture to avoid MongoDB dependency."""
    yield


@pytest.fixture(scope="session")
def mongodb():
    """Override the mongodb fixture to avoid MongoDB dependency."""
    yield None


@pytest.fixture(scope="session")
def app():
    """Override the app fixture to avoid Flask app dependency."""
    yield None
