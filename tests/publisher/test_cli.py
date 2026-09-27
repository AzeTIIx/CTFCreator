"""Tests for CLI argument parsing."""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "challenges"

from ctfcreator.publisher.cli import parse_args, read_version_from_file
from ctfcreator.publisher.models import PublishConfig


def test_parse_args_requires_version(tmp_path: Path):
    with pytest.raises(SystemExit):
        parse_args([str(tmp_path)])


def test_parse_args_with_version(tmp_path: Path):
    config = parse_args([str(tmp_path), "--version", "2026.1", "--dry-run"])
    assert config.version == "2026.1"
    assert config.dry_run is True


def test_version_from_file(fixtures_root: Path):
    version = read_version_from_file(fixtures_root)
    assert version == "2026.1"


def test_invalid_registry_rejected(tmp_path: Path):
    with pytest.raises(SystemExit):
        parse_args([str(tmp_path), "--version", "2026.1", "--registry", "localhost:5000;rm -rf"])


def test_non_loopback_requires_confirmation(tmp_path: Path):
    with pytest.raises(SystemExit):
        parse_args([str(tmp_path), "--version", "2026.1", "--bind-address", "0.0.0.0"])


def test_non_loopback_with_confirmation(tmp_path: Path):
    config = parse_args([
        str(tmp_path), "--version", "2026.1",
        "--bind-address", "0.0.0.0",
        "--allow-non-loopback-registry",
    ])
    assert config.bind_address == "0.0.0.0"


def test_shell_separator_in_version_rejected(tmp_path: Path):
    with pytest.raises(SystemExit):
        parse_args([str(tmp_path), "--version", "2026.1;echo"])
