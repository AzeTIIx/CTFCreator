"""Tests for single-image publication with mocked Docker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctfcreator.publisher.cli import run_publication
from ctfcreator.publisher.discovery import classify_challenge
from ctfcreator.publisher.docker_cli import CommandResult, DockerCLI
from ctfcreator.publisher.models import ChallengeStatus, ChallengeType, OverallStatus, PublishConfig
from ctfcreator.publisher.validation import compute_image_reference


class MockRunner:
    def __init__(self):
        self.commands: list[list[str]] = []
        self.images: dict[str, dict] = {}

    def run(self, cmd: list[str], *, timeout: float | None = None, cwd: str | None = None, stream: bool | None = None, quiet: bool = False) -> CommandResult:
        self.commands.append(cmd)

        if cmd[:2] == ["docker", "info"]:
            return CommandResult(0, "24.0.0", "")
        if cmd[:3] == ["docker", "compose", "version"]:
            return CommandResult(0, "v2", "")

        if cmd[:2] == ["docker", "build"]:
            tag = cmd[cmd.index("-t") + 1]
            self.images[tag] = {
                "Config": {"User": "appuser", "ExposedPorts": {"8080/tcp": {}}},
                "RepoDigests": [],
                "Id": "sha256:built123",
            }
            return CommandResult(0, "Successfully built", "")

        if cmd[:2] == ["docker", "push"]:
            return CommandResult(0, "pushed", "")

        if cmd[:2] == ["docker", "pull"]:
            return CommandResult(0, "pulled", "")

        if cmd[:3] == ["docker", "image", "inspect"]:
            ref = cmd[3]
            if ref in self.images:
                return CommandResult(0, json.dumps([self.images[ref]]), "")
            return CommandResult(1, "", "not found")

        if cmd[:2] == ["docker", "history"]:
            return CommandResult(0, "IMAGE CREATED", "")

        if cmd[:2] == ["docker", "save"]:
            return CommandResult(0, b"".decode("latin-1") if False else "", "")

        if cmd[:2] == ["docker", "container"]:
            return CommandResult(1, "", "not found")

        if cmd[:2] == ["docker", "run"]:
            return CommandResult(0, "registry-id", "")

        return CommandResult(0, "", "")


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "challenges"


def test_dry_run_single(tmp_path: Path, fixtures_root: Path):
    import shutil
    root = tmp_path / "challenges"
    shutil.copytree(fixtures_root / "web-idor", root / "web-idor")
    config = PublishConfig(
        root=root,
        registry="localhost:5000",
        version="2026.1",
        dry_run=True,
        output_dir=tmp_path / "out",
    )
    manifest, code = run_publication(config, docker=DockerCLI(MockRunner()))
    assert code == 0
    assert manifest.overall_status == OverallStatus.DRY_RUN
    ch = manifest.challenges[0]
    assert ch.type == ChallengeType.SINGLE_IMAGE
    assert ch.images[0].reference == "localhost:5000/web-idor:2026.1"


def test_static_never_builds(fixtures_root: Path, tmp_path: Path):
    runner = MockRunner()
    config = PublishConfig(
        root=fixtures_root,
        registry="localhost:5000",
        version="2026.1",
        dry_run=True,
        output_dir=tmp_path / "out",
        challenges=["static-challenge"],
    )
    manifest, code = run_publication(config, docker=DockerCLI(runner))
    assert code == 0
    ch = manifest.challenges[0]
    assert ch.status == ChallengeStatus.SKIPPED_STATIC
    assert ch.images == []
    assert not any(c[:2] == ["docker", "build"] for c in runner.commands)


def test_invalid_blocks_before_build(tmp_path: Path):
    import shutil
    invalid_root = Path(__file__).resolve().parent / "fixtures" / "invalid-challenges"
    root = tmp_path / "challenges"
    shutil.copytree(invalid_root / "incomplete-challenge", root / "incomplete-challenge")
    runner = MockRunner()
    config = PublishConfig(
        root=root,
        registry="localhost:5000",
        version="2026.1",
        output_dir=tmp_path / "out",
        challenges=["incomplete-challenge"],
    )

    import ctfcreator.publisher.registry as reg_mod
    class HealthyClient(reg_mod.RegistryClient):
        def check_health(self):
            from ctfcreator.publisher.registry import RegistryHealth
            return RegistryHealth(healthy=True)

    old = reg_mod.RegistryClient
    reg_mod.RegistryClient = HealthyClient
    try:
        manifest, code = run_publication(config, docker=DockerCLI(runner))
    finally:
        reg_mod.RegistryClient = old

    assert code != 0
    assert not any(c[:2] == ["docker", "build"] for c in runner.commands)
