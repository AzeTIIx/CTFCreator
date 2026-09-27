"""Tests for challenge discovery."""

from pathlib import Path

import pytest

from ctfcreator.publisher.discovery import (
    classify_challenge,
    detect_slug_collisions,
    discover_challenges,
    normalize_slug,
)
from ctfcreator.publisher.models import ChallengeType


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "challenges"


def test_static_challenge_discovery(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "static-challenge")
    assert ch.challenge_type == ChallengeType.STATIC


def test_single_image_discovery(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "web-idor")
    assert ch.challenge_type == ChallengeType.SINGLE_IMAGE
    assert ch.dockerfile is not None


def test_compose_discovery(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "network-exposure")
    assert ch.challenge_type == ChallengeType.MULTI_SERVICE
    assert ch.compose_file.name == "docker-compose.yml"


def test_historical_compose_alias(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "historical-compose")
    assert ch.challenge_type == ChallengeType.MULTI_SERVICE
    assert ch.compose_file.name == "docker-compose.build.yml"
    assert any("historical alias" in w for w in ch.warnings)


def test_incomplete_challenge_invalid():
    invalid_root = Path(__file__).resolve().parent / "fixtures" / "invalid-challenges"
    ch = classify_challenge(invalid_root / "incomplete-challenge")
    assert ch.challenge_type == ChallengeType.INVALID
    assert any("solve.md" in e for e in ch.errors)


def test_hidden_directory_ignored(fixtures_root: Path, tmp_path: Path):
    hidden = tmp_path / ".hidden-challenge"
    hidden.mkdir()
    (hidden / "README.md").write_text("# hidden")
    (hidden / "solve.md").write_text("# sol")
    discovered = discover_challenges(tmp_path)
    assert len(discovered) == 0


def test_ignored_dirs(fixtures_root: Path):
    discovered = discover_challenges(fixtures_root)
    slugs = {c.slug for c in discovered}
    assert "dist" not in slugs
    assert "scripts" not in slugs
    assert "tests" not in slugs


def test_slug_collision_detection():
    collision_root = Path(__file__).resolve().parent / "fixtures" / "collision-challenges"
    # Copy web-idor alongside Web_IDOR for collision test
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        shutil.copytree(
            Path(__file__).resolve().parent / "fixtures" / "challenges" / "web-idor",
            tmp_path / "web-idor",
        )
        shutil.copytree(collision_root / "Web_IDOR", tmp_path / "Web_IDOR")
        discovered = discover_challenges(tmp_path)
        collisions = detect_slug_collisions(discovered)
        assert any("web-idor" in c.lower() for c in collisions)


def test_normalize_slug():
    assert normalize_slug("Web-IDOR") == "web-idor"
    assert normalize_slug("network_exposure") == "network-exposure"


def test_discover_all_types(fixtures_root: Path):
    discovered = discover_challenges(fixtures_root)
    types = {c.challenge_type for c in discovered}
    assert ChallengeType.STATIC in types
    assert ChallengeType.SINGLE_IMAGE in types
    assert ChallengeType.MULTI_SERVICE in types
