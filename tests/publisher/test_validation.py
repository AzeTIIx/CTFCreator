"""Tests for preflight validation."""

from pathlib import Path

import pytest

from ctfcreator.publisher.discovery import classify_challenge
from ctfcreator.publisher.models import ChallengeType
from ctfcreator.publisher.validation import (
    ValidationError,
    compute_image_reference,
    validate_challenge_preflight,
    validate_dockerfile,
    validate_registry,
    validate_shell_safe,
    validate_version,
)


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "challenges"


def test_compute_image_reference_single():
    ref = compute_image_reference("localhost:5000", "web-idor", "2026.1")
    assert ref == "localhost:5000/web-idor:2026.1"


def test_compute_image_reference_compose():
    ref = compute_image_reference("localhost:5000", "network-exposure", "2026.1", "public-app")
    assert ref == "localhost:5000/network-exposure-public-app:2026.1"


def test_latest_rejected():
    with pytest.raises(ValidationError):
        compute_image_reference("localhost:5000", "web-idor", "latest")


def test_invalid_version():
    with pytest.raises(ValidationError):
        validate_version("")


def test_invalid_registry():
    with pytest.raises(ValidationError):
        validate_registry("http://localhost:5000")


def test_shell_unsafe_value():
    with pytest.raises(ValidationError):
        validate_shell_safe("foo;bar", "test")


def test_single_image_preflight_ok(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "web-idor")
    errors = validate_challenge_preflight(ch)
    assert errors == []


def test_incomplete_invalid():
    invalid_root = Path(__file__).resolve().parent / "fixtures" / "invalid-challenges"
    ch = classify_challenge(invalid_root / "incomplete-challenge")
    assert ch.challenge_type == ChallengeType.INVALID


def test_dockerfile_requires_user(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine\nCMD echo hi\n")
    errors = validate_dockerfile(df, "test")
    assert any("USER" in e for e in errors)


def test_real_flag_blocked(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine\nUSER nobody\nENV FLAG=flag{real_secret_flag_here}\n")
    errors = validate_dockerfile(df, "test")
    assert any("flag" in e.lower() for e in errors)


def test_placeholder_flag_allowed(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine\nUSER nobody\nENV FLAG=flag{placeholder}\n")
    errors = validate_dockerfile(df, "test")
    flag_errors = [e for e in errors if "flag" in e.lower()]
    assert flag_errors == []


# --- .dockerignore-aware secret scan -------------------------------------------------

from ctfcreator.publisher.validation import is_dockerignored, load_dockerignore  # noqa: E402


def _rules(tmp_path, content):
    (tmp_path / ".dockerignore").write_text(content, encoding="utf-8")
    return load_dockerignore(tmp_path)


def test_dockerignore_root_anchored(tmp_path):
    rules = _rules(tmp_path, "*.md\nchallenge.yml\n")
    assert is_dockerignored("README.md", rules)
    assert is_dockerignored("challenge.yml", rules)
    # like docker: "*.md" does not match in subdirectories
    assert not is_dockerignored("src/notes.md", rules)


def test_dockerignore_double_star_and_dirs(tmp_path):
    rules = _rules(tmp_path, "**/*.md\ntests/\n")
    assert is_dockerignored("src/notes.md", rules)
    assert is_dockerignored("tests/test_x.py", rules)
    assert not is_dockerignored("src/app.py", rules)


def test_dockerignore_exception(tmp_path):
    rules = _rules(tmp_path, "*.sh\n!entrypoint.sh\n")
    assert is_dockerignored("check_challenge.sh", rules)
    assert not is_dockerignored("entrypoint.sh", rules)


def test_preflight_ignores_excluded_teacher_files(tmp_path):
    from ctfcreator.publisher.discovery import discover_challenges  # noqa: F401
    from ctfcreator.publisher.validation import validate_challenge_preflight
    from ctfcreator.publisher.models import DiscoveredChallenge, ChallengeType

    chal = tmp_path / "demo"
    (chal / "src").mkdir(parents=True)
    (chal / "Dockerfile").write_text(
        "FROM python:3.12-slim\nCOPY src/ /app/\nUSER nobody\n", encoding="utf-8"
    )
    (chal / ".dockerignore").write_text(
        ".git\nsolve.md\ntests\nexpected\n*.md\nchallenge.yml\n", encoding="utf-8"
    )
    (chal / "README.md").write_text("flag: CTF{real_flag_in_readme}", encoding="utf-8")
    (chal / "challenge.yml").write_text("flags: [CTF{real_flag_in_yaml}]", encoding="utf-8")
    (chal / "src" / "app.py").write_text("FLAG = os.environ['FLAG']\n", encoding="utf-8")

    c = DiscoveredChallenge(slug="demo", path=chal, challenge_type=ChallengeType.SINGLE_IMAGE,
                            dockerfile=chal / "Dockerfile")
    assert validate_challenge_preflight(c) == []

    # a flag inside the build context is still caught
    (chal / "src" / "app.py").write_text("FLAG = 'CTF{real_flag_in_code}'\n", encoding="utf-8")
    errs = validate_challenge_preflight(c)
    assert any("Flag pattern" in e and "app.py" in e for e in errs)


def test_allow_static_flags_only_relaxes_flags(tmp_path):
    from ctfcreator.publisher.validation import validate_challenge_preflight
    from ctfcreator.publisher.models import DiscoveredChallenge, ChallengeType

    chal = tmp_path / "demo"
    (chal / "src").mkdir(parents=True)
    (chal / "Dockerfile").write_text(
        "FROM python:3.12-slim\nENV FLAG=CTF{static_flag_ok}\nCOPY src/ /app/\nUSER nobody\n",
        encoding="utf-8",
    )
    (chal / ".dockerignore").write_text(".git\nsolve.md\ntests\nexpected\n", encoding="utf-8")
    (chal / "src" / "app.py").write_text("FLAG = 'CTF{static_flag_ok}'\n", encoding="utf-8")
    c = DiscoveredChallenge(slug="demo", path=chal, challenge_type=ChallengeType.SINGLE_IMAGE,
                            dockerfile=chal / "Dockerfile")

    assert any("Flag pattern" in e for e in validate_challenge_preflight(c))
    assert validate_challenge_preflight(c, allow_static_flags=True) == []

    (chal / "src" / "key.pem").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n", encoding="utf-8"
    )
    errs = validate_challenge_preflight(c, allow_static_flags=True)
    assert any("Private key" in e for e in errs)


def test_cli_allow_static_flags_option(tmp_path):
    from ctfcreator.publisher.cli import parse_args
    (tmp_path / "VERSION").write_text("2026.1", encoding="utf-8")
    assert parse_args([str(tmp_path)]).allow_static_flags is False
    assert parse_args([str(tmp_path), "--allow-static-flags"]).allow_static_flags is True
