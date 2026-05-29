"""Pytest fixtures for ConfigGuard tests."""
import pytest
from pathlib import Path
import json
import yaml


@pytest.fixture
def test_cases_dir():
    return Path(__file__).parent / "cases"


@pytest.fixture
def load_test_case(test_cases_dir):
    def _load(case_name: str):
        case_dir = test_cases_dir / case_name
        config_file = case_dir / "config.txt"
        expected_file = case_dir / "expected.json"
        metadata_file = case_dir / "metadata.yaml"

        config_text = config_file.read_text()
        expected = json.loads(expected_file.read_text())
        metadata = yaml.safe_load(metadata_file.read_text())

        return {
            "config": config_text,
            "expected": expected,
            "metadata": metadata,
        }
    return _load