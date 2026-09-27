"""Tests for registry management with mocked Docker runner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from ctfcreator.publisher.docker_cli import CommandResult, DockerCLI
from ctfcreator.publisher.models import PublishConfig
from ctfcreator.publisher.registry import (
    RegistryClient,
    RegistryError,
    RegistryHealth,
    check_immutability,
    ensure_registry,
    wait_for_registry,
)


class MockRunner:
    """Simulated command runner for Docker CLI."""

    def __init__(self):
        self.commands: list[list[str]] = []
        self.responses: dict[str, CommandResult] = {}
        self.containers: dict[str, dict[str, Any]] = {}

    def run(self, cmd: list[str], *, timeout: float | None = None, cwd: str | None = None, stream: bool | None = None, quiet: bool = False) -> CommandResult:
        self.commands.append(cmd)
        key = " ".join(cmd)
        if key in self.responses:
            return self.responses[key]

        if cmd[:2] == ["docker", "info"]:
            return CommandResult(0, "24.0.0", "")

        if cmd[:3] == ["docker", "compose", "version"]:
            return CommandResult(0, "v2.0.0", "")

        if cmd[:3] == ["docker", "container", "inspect"]:
            name = cmd[3]
            if name in self.containers:
                return CommandResult(0, json.dumps([self.containers[name]]), "")
            return CommandResult(1, "", "not found")

        if cmd[:2] == ["docker", "start"]:
            name = cmd[2]
            if name in self.containers:
                self.containers[name]["State"] = {"Running": True}
                return CommandResult(0, name, "")
            return CommandResult(1, "", "not found")

        if cmd[:2] == ["docker", "run"]:
            name_idx = cmd.index("--name") + 1 if "--name" in cmd else None
            if name_idx:
                name = cmd[name_idx]
                self.containers[name] = {
                    "Name": f"/{name}",
                    "State": {"Running": True},
                    "HostConfig": {
                        "PortBindings": {
                            "5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5000"}]
                        }
                    },
                }
            return CommandResult(0, "container-id", "")

        return CommandResult(0, "", "")

    def set_inspect(self, name: str, data: dict):
        self.containers[name] = data


class MockRegistryClient(RegistryClient):
    def __init__(self, healthy: bool = True):
        super().__init__("localhost:5000")
        self._healthy = healthy
        self._digests: dict[str, str] = {}

    def check_health(self) -> RegistryHealth:
        if self._healthy:
            return RegistryHealth(healthy=True)
        return RegistryHealth(healthy=False, message="unavailable")

    def get_tag_digest(self, repository: str, tag: str) -> str | None:
        return self._digests.get(f"{repository}:{tag}")


def _config(**kwargs) -> PublishConfig:
    defaults = dict(
        root=__import__("pathlib").Path("/tmp/challenges"),
        registry="localhost:5000",
        version="2026.1",
    )
    defaults.update(kwargs)
    return PublishConfig(**defaults)


def test_healthy_registry_reused():
    runner = MockRunner()
    docker = DockerCLI(runner)
    config = _config(dry_run=False)

    # Patch ensure to use mock - registry healthy from start
    original = RegistryClient.check_health

    class HealthyClient(RegistryClient):
        def check_health(self):
            return RegistryHealth(healthy=True)

    import ctfcreator.publisher.registry as reg_mod
    old_client = reg_mod.RegistryClient
    reg_mod.RegistryClient = HealthyClient
    try:
        health = ensure_registry(config, docker)
        assert health.healthy
        assert not any("run" in " ".join(c) for c in runner.commands if c[:2] == ["docker", "run"])
    finally:
        reg_mod.RegistryClient = old_client


def test_stopped_container_started():
    runner = MockRunner()
    runner.set_inspect("ctfd-registry", {
        "State": {"Running": False},
        "HostConfig": {
            "PortBindings": {"5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5000"}]}
        },
    })
    docker = DockerCLI(runner)
    config = _config()

    call_count = [0]

    class FlappingClient(RegistryClient):
        def check_health(self):
            call_count[0] += 1
            if call_count[0] <= 1:
                return RegistryHealth(healthy=False)
            return RegistryHealth(healthy=True)

    import ctfcreator.publisher.registry as reg_mod
    old = reg_mod.RegistryClient
    reg_mod.RegistryClient = FlappingClient
    try:
        health = ensure_registry(config, docker)
        assert health.healthy
        assert any(
            len(c) >= 3 and c[-2] == "start" and c[-1] == "ctfd-registry"
            for c in runner.commands
        )
    finally:
        reg_mod.RegistryClient = old


def test_incompatible_running_container_fails():
    runner = MockRunner()
    runner.set_inspect("ctfd-registry", {
        "State": {"Running": True},
        "HostConfig": {"PortBindings": {}},
    })
    docker = DockerCLI(runner)
    config = _config()

    class UnhealthyClient(RegistryClient):
        def check_health(self):
            return RegistryHealth(healthy=False, message="bad")

    import ctfcreator.publisher.registry as reg_mod
    old = reg_mod.RegistryClient
    reg_mod.RegistryClient = UnhealthyClient
    try:
        with pytest.raises(RegistryError):
            ensure_registry(config, docker)
    finally:
        reg_mod.RegistryClient = old


def test_no_create_registry_fails():
    runner = MockRunner()
    docker = DockerCLI(runner)
    config = _config(no_create_registry=True)

    class UnhealthyClient(RegistryClient):
        def check_health(self):
            return RegistryHealth(healthy=False)

    import ctfcreator.publisher.registry as reg_mod
    old = reg_mod.RegistryClient
    reg_mod.RegistryClient = UnhealthyClient
    try:
        with pytest.raises(RegistryError):
            ensure_registry(config, docker)
    finally:
        reg_mod.RegistryClient = old


def test_dry_run_skips_registry():
    runner = MockRunner()
    docker = DockerCLI(runner)
    config = _config(dry_run=True)
    health = ensure_registry(config, docker)
    assert health.healthy
    assert runner.commands == []


def test_immutability_same_digest():
    client = MockRegistryClient()
    client._digests["web-idor:2026.1"] = "sha256:abc123"
    action, idempotent, remote = check_immutability(
        client, "web-idor", "2026.1", "sha256:abc123"
    )
    assert action == "skip"
    assert idempotent is True


def test_immutability_different_digest_blocked():
    client = MockRegistryClient()
    client._digests["web-idor:2026.1"] = "sha256:old"
    action, idempotent, remote = check_immutability(
        client, "web-idor", "2026.1", "sha256:new", force=False
    )
    assert action == "block"
    assert idempotent is False


def test_immutability_force_allows():
    client = MockRegistryClient()
    client._digests["web-idor:2026.1"] = "sha256:old"
    action, _, _ = check_immutability(
        client, "web-idor", "2026.1", "sha256:new", force=True
    )
    assert action == "push"
