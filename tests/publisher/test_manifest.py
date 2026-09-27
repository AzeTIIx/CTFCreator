"""Tests for manifest generation."""

import json
from pathlib import Path

import pytest

from ctfcreator.publisher.manifest import (
    _atomic_write,
    generate_env_file,
    generate_report_md,
    slug_to_env_var,
    write_manifest_atomic,
)
from ctfcreator.publisher.models import (
    ChallengeResult,
    ChallengeStatus,
    ChallengeType,
    ImagePublication,
    OverallStatus,
    PublicationManifest,
    PublishConfig,
)


def test_slug_to_env_var():
    assert slug_to_env_var("web-idor") == "WEB_IDOR_IMAGE"
    assert slug_to_env_var("network-exposure", "public-app") == "NETWORK_EXPOSURE_PUBLIC_APP_IMAGE"


def test_env_file_generation():
    manifest = PublicationManifest(
        registry="localhost:5000",
        version="2026.1",
        challenges=[
            ChallengeResult(
                slug="web-idor",
                path="web-idor",
                type=ChallengeType.SINGLE_IMAGE,
                status=ChallengeStatus.PUBLISHED,
                images=[
                    ImagePublication(
                        service=None,
                        reference="localhost:5000/web-idor:2026.1",
                        digest="sha256:abc",
                        verified=True,
                    )
                ],
            )
        ],
    )
    env = generate_env_file(manifest)
    assert "WEB_IDOR_IMAGE=localhost:5000/web-idor:2026.1" in env


def test_atomic_write(tmp_path: Path):
    target = tmp_path / "test.json"
    _atomic_write(target, '{"ok": true}')
    assert target.read_text() == '{"ok": true}'


def test_manifest_atomic_write(tmp_path: Path):
    config = PublishConfig(
        root=tmp_path,
        registry="localhost:5000",
        version="2026.1",
        output_dir=tmp_path / "out",
    )
    manifest = PublicationManifest(
        registry="localhost:5000",
        version="2026.1",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        overall_status=OverallStatus.SUCCESS,
        challenges=[],
    )
    write_manifest_atomic(manifest, config)

    json_path = config.output_dir / "publication-manifest.json"
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["overall_status"] == "success"

    md_path = config.output_dir / "publication-report.md"
    assert md_path.exists()

    env_path = config.output_dir / "ctfd-images.env"
    assert env_path.exists()


def test_report_md_contains_status():
    manifest = PublicationManifest(
        registry="localhost:5000",
        version="2026.1",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:01:00Z",
        overall_status=OverallStatus.DRY_RUN,
    )
    report = generate_report_md(manifest)
    assert "dry-run" in report
