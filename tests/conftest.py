"""Shared pytest fixtures for the test suite."""

import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_terraform_dir():
    return FIXTURES_DIR / "valid_terraform"


@pytest.fixture
def invalid_terraform_dir():
    return FIXTURES_DIR / "invalid_terraform"
