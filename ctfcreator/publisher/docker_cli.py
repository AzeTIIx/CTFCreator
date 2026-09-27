"""Docker and Docker Compose CLI wrappers."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .logging_utils import format_short_docker_cmd, get_docker_logger, truncate_log_output


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class DockerNotFoundError(Exception):
    """Raised when the Docker CLI cannot be located or reached."""


_DOCKER_EXE: str | None = None

_WINDOWS_DOCKER_CANDIDATES = (
    Path(os.environ.get("LOCALAPPDATA", ""))
    / "Programs"
    / "Docker"
    / "Docker"
    / "resources"
    / "bin"
    / "docker.exe",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    / "Docker"
    / "Docker"
    / "resources"
    / "bin"
    / "docker.exe",
)

# Commands whose output should go straight to the terminal (Docker colors/progress).
_STREAM_SUBCOMMANDS = frozenset({"build", "push"})


def resolve_docker_executable() -> str:
    """Locate docker CLI, including Docker Desktop per-user installs on Windows."""
    global _DOCKER_EXE
    if _DOCKER_EXE is not None:
        return _DOCKER_EXE

    found = shutil.which("docker")
    if found:
        _DOCKER_EXE = found
        return found

    if sys.platform == "win32":
        for candidate in _WINDOWS_DOCKER_CANDIDATES:
            if candidate.is_file():
                _DOCKER_EXE = str(candidate)
                return _DOCKER_EXE

    _DOCKER_EXE = "docker"
    return _DOCKER_EXE


def docker_command(*args: str) -> list[str]:
    """Build a docker argv list with a resolved executable."""
    return [resolve_docker_executable(), *args]


def docker_install_hint() -> str:
    exe = resolve_docker_executable()
    if sys.platform == "win32" and exe != "docker" and Path(exe).is_file():
        return (
            f"Docker found at: {exe}\n"
            "Add this directory to your user PATH, or restart the terminal "
            "after installing Docker Desktop:\n"
            f"  {Path(exe).parent}"
        )
    if sys.platform == "win32":
        return (
            "Install Docker Desktop, start it, then add to PATH:\n"
            "  %LOCALAPPDATA%\\Programs\\Docker\\Docker\\resources\\bin"
        )
    return "Install Docker Engine and ensure `docker` is on PATH."


def should_stream_docker_output(cmd: list[str]) -> bool:
    """Return True when Docker should write directly to the user's terminal."""
    if not cmd or len(cmd) < 2:
        return False
    args = cmd[1:]
    if args[0] == "compose":
        return "build" in args
    return args[0] in _STREAM_SUBCOMMANDS


class CommandRunner(Protocol):
    def run(
        self,
        cmd: list[str],
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        stream: bool | None = None,
        quiet: bool = False,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Execute subprocess commands without shell interpolation."""

    def run(
        self,
        cmd: list[str],
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        stream: bool | None = None,
        quiet: bool = False,
    ) -> CommandResult:
        del stream  # base runner always captures
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=timeout,
                cwd=cwd,
            )
            return CommandResult(result.returncode, result.stdout, result.stderr)
        except FileNotFoundError as exc:
            executable = cmd[0] if cmd else "docker"
            raise DockerNotFoundError(
                f"Command not found: {executable}. {docker_install_hint()}"
            ) from exc


class LoggingSubprocessRunner:
    """Run Docker commands: stream build/push to TTY, keep inspect/config quiet."""

    def __init__(
        self,
        inner: CommandRunner | None = None,
        *,
        verbose: bool = False,
        logger: logging.Logger | None = None,
    ):
        self.inner = inner or SubprocessRunner()
        self.verbose = verbose
        self.logger = logger or get_docker_logger()

    def run(
        self,
        cmd: list[str],
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        stream: bool | None = None,
        quiet: bool = False,
    ) -> CommandResult:
        do_stream = should_stream_docker_output(cmd) if stream is None else stream
        label = format_short_docker_cmd(cmd, cwd=cwd)

        if do_stream:
            try:
                completed = subprocess.run(
                    cmd,
                    cwd=cwd,
                    timeout=timeout,
                    check=False,
                    shell=False,
                )
            except FileNotFoundError as exc:
                self.logger.error("docker: command not found")
                raise DockerNotFoundError(
                    f"Command not found: docker. {docker_install_hint()}"
                ) from exc

            if completed.returncode != 0:
                self.logger.error("%s: exit code %d", label, completed.returncode)
            return CommandResult(completed.returncode, "", "")

        if self.verbose:
            if cwd:
                self.logger.debug("$ %s  (cwd=%s)", label, cwd)
            else:
                self.logger.debug("$ %s", label)

        try:
            result = self.inner.run(cmd, timeout=timeout, cwd=cwd, stream=False, quiet=quiet)
        except DockerNotFoundError:
            self.logger.error("docker: command not found")
            raise

        if result.returncode != 0:
            detail = truncate_log_output(result.stderr or result.stdout)
            log_fn = self.logger.debug if quiet else self.logger.error
            if detail:
                log_fn("%s", detail)
            elif not quiet:
                self.logger.error("%s: exit code %d", label, result.returncode)
        elif self.verbose and result.stdout.strip():
            self.logger.debug("%s", truncate_log_output(result.stdout))

        return result


class DockerCLI:
    """Thin wrapper around official docker and docker compose CLIs."""

    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or SubprocessRunner()

    def docker(
        self,
        *args: str,
        timeout: float | None = None,
        cwd: str | None = None,
        stream: bool | None = None,
        quiet: bool = False,
    ) -> CommandResult:
        return self.runner.run(
            docker_command(*args), timeout=timeout, cwd=cwd, stream=stream, quiet=quiet
        )

    def compose(
        self,
        compose_file: str,
        *args: str,
        cwd: str | None = None,
        timeout: float | None = None,
        stream: bool | None = None,
        quiet: bool = False,
    ) -> CommandResult:
        cmd = docker_command("compose", "-f", compose_file, *args)
        return self.runner.run(cmd, timeout=timeout, cwd=cwd, stream=stream, quiet=quiet)

    def is_available(self) -> bool:
        try:
            return self.docker("info").returncode == 0
        except DockerNotFoundError:
            return False

    def ensure_available(self) -> None:
        """Verify CLI presence and daemon connectivity with actionable errors."""
        log = get_docker_logger()
        exe = resolve_docker_executable()
        log.debug("Docker CLI: %s", exe)

        if exe == "docker" and shutil.which("docker") is None:
            raise DockerNotFoundError(f"Docker CLI not found. {docker_install_hint()}")
        if not Path(exe).is_file() and shutil.which("docker") is None:
            raise DockerNotFoundError(f"Docker CLI not found: {exe}. {docker_install_hint()}")

        result = self.docker("info")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "daemon unreachable").strip()
            raise DockerNotFoundError(
                f"Docker is installed but the daemon is not responding: {detail}\n"
                "Start Docker Desktop and retry."
            )

        version = self.docker("version", "--format", "{{.Server.Version}}")
        if version.returncode == 0 and version.stdout.strip():
            log.info("Server version: %s", version.stdout.strip())

        compose = self.compose_version()
        if compose:
            line = compose.splitlines()[0]
            log.info("%s", line)

        log.info("Publish mode: build and push images only (challenge containers are not started)")

    def compose_version(self) -> str | None:
        try:
            result = self.docker("compose", "version")
        except DockerNotFoundError:
            return None
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def save_image_bytes(self, reference: str) -> bytes:
        """Run docker save and return raw archive bytes."""
        try:
            result = subprocess.run(
                docker_command("save", reference),
                capture_output=True,
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise DockerNotFoundError(
                f"Command not found: docker save. {docker_install_hint()}"
            ) from exc
        if result.returncode != 0:
            return b""
        return result.stdout

    def container_exists(self, name: str) -> bool:
        return self.docker("container", "inspect", name, quiet=True).returncode == 0

    def container_is_running(self, name: str) -> bool:
        data = self.container_inspect(name)
        if not data:
            return False
        return bool(data.get("State", {}).get("Running", False))

    def container_inspect(self, name: str) -> dict | None:
        result = self.docker("container", "inspect", name, quiet=True)
        if result.returncode != 0:
            return None
        try:
            items = json.loads(result.stdout)
            return items[0] if items else None
        except json.JSONDecodeError:
            return None

    def inspect_image(self, reference: str) -> dict | None:
        result = self.docker("image", "inspect", reference, quiet=True)
        if result.returncode != 0:
            return None
        try:
            items = json.loads(result.stdout)
            return items[0] if items else None
        except json.JSONDecodeError:
            return None

    def image_digest(self, reference: str) -> str | None:
        data = self.inspect_image(reference)
        if not data:
            return None
        repo_digests = data.get("RepoDigests") or []
        if repo_digests:
            digest_ref = repo_digests[0]
            return digest_ref.split("@")[-1] if "@" in digest_ref else digest_ref
        image_id = data.get("Id", "")
        if image_id.startswith("sha256:"):
            return image_id
        return image_id or None

    def image_history(self, reference: str) -> str:
        result = self.docker("history", "--no-trunc", reference)
        if result.returncode != 0:
            return ""
        return result.stdout + result.stderr
