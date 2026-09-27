"""Tests for multi-service compose publication."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ctfcreator.publisher.build import parse_compose_config, resolve_compose_services
from ctfcreator.publisher.discovery import classify_challenge
from ctfcreator.publisher.docker_cli import CommandResult, DockerCLI
from ctfcreator.publisher.models import PublishConfig
from ctfcreator.publisher.manifest import generate_ctfd_compose


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "challenges"


class ComposeMockRunner:
    def run(self, cmd: list[str], *, timeout: float | None = None, cwd: str | None = None, stream: bool | None = None, quiet: bool = False) -> CommandResult:
        if cmd[:5] == ["docker", "compose", "-f"] and "config" in cmd:
            compose_file = cmd[3]
            import yaml as y
            with open(compose_file) as f:
                data = y.safe_load(f)
            normalized = {"services": {}}
            for name, svc in data.get("services", {}).items():
                ns = dict(svc)
                if "build" in svc:
                    ctx = svc["build"].get("context", ".") if isinstance(svc["build"], dict) else svc["build"]
                    ns["build"] = {"context": str(Path(compose_file).parent / ctx), "dockerfile": "Dockerfile"}
                normalized["services"][name] = ns
            return CommandResult(0, json.dumps(normalized), "")
        return CommandResult(0, "", "")


def test_compose_service_resolution(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "network-exposure")
    config = PublishConfig(root=fixtures_root, registry="localhost:5000", version="2026.1")
    docker = DockerCLI(ComposeMockRunner())
    services = resolve_compose_services(ch, config, docker)

    built = [s for s in services if s.built]
    external = [s for s in services if s.is_external]
    assert len(built) == 2
    assert len(external) == 1
    assert external[0].name == "redis"

    refs = {s.name: s.registry_reference for s in built}
    assert refs["public-app"] == "localhost:5000/network-exposure-public-app:2026.1"
    assert refs["internal-admin"] == "localhost:5000/network-exposure-internal-admin:2026.1"


def test_ctfd_compose_no_build(fixtures_root: Path):
    ch = classify_challenge(fixtures_root / "network-exposure")
    config = PublishConfig(root=fixtures_root, registry="localhost:5000", version="2026.1")
    docker = DockerCLI(ComposeMockRunner())
    services = resolve_compose_services(ch, config, docker)
    compose_config = parse_compose_config(ch.compose_file, ch.path, docker)
    ctfd = generate_ctfd_compose(ch, services, compose_config, config)

    content = yaml.dump(ctfd)
    assert "build:" not in content
    assert "localhost:5000/network-exposure-public-app:2026.1" in content
    assert "redis:7-alpine" in content


def test_service_without_image_gets_deterministic_tag(fixtures_root: Path, tmp_path: Path):
    compose_dir = tmp_path / "no-image-svc"
    compose_dir.mkdir()
    (compose_dir / "README.md").write_text("# test")
    (compose_dir / "solve.md").write_text("# sol")
    (compose_dir / "Dockerfile").write_text("FROM alpine\nUSER nobody\nEXPOSE 80\n")
    (compose_dir / ".dockerignore").write_text(".git\nsolve.md\ntests\nexpected\n")
    (compose_dir / "docker-compose.yml").write_text(
        "services:\n  app:\n    build: .\n"
    )

    ch = classify_challenge(compose_dir)
    config = PublishConfig(root=tmp_path, registry="localhost:5000", version="2026.1")
    docker = DockerCLI(ComposeMockRunner())
    services = resolve_compose_services(ch, config, docker)
    assert services[0].local_image == "no-image-svc-app:local-build"


def test_ctfd_override_with_build_rejected(fixtures_root: Path, tmp_path: Path):
    override = tmp_path / "docker-compose.ctfd.yml"
    override.write_text("services:\n  app:\n    build: .\n    image: x:1\n")
    from ctfcreator.publisher.validation import validate_ctfd_override
    errors = validate_ctfd_override(override, "test")
    assert any("build" in e for e in errors)
