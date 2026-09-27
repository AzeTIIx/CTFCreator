"""Shared test helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _normalize_docker_cli_for_tests(monkeypatch):
    """Mocks unitaires : argv docker standard."""
    monkeypatch.setattr("ctfcreator.publisher.docker_cli._DOCKER_EXE", None)
    monkeypatch.setattr("ctfcreator.publisher.docker_cli.resolve_docker_executable", lambda: "docker")


@pytest.fixture
def fixtures_root() -> Path:
    return FIXTURES / "challenges"


@pytest.fixture
def tmp_challenges(tmp_path: Path) -> Path:
    """Copy minimal fixture set to temp dir."""
    import shutil
    src = FIXTURES / "challenges"
    dst = tmp_path / "challenges"
    if src.exists():
        shutil.copytree(src, dst)
    return dst
