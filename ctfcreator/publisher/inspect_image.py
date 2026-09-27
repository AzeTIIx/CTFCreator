"""Post-build image inspection."""

from __future__ import annotations

import tarfile
from io import BytesIO

from .docker_cli import DockerCLI
from .validation import FLAG_PATTERNS, ALLOWED_PLACEHOLDER_FLAGS, PRIVATE_KEY_PATTERN, SECRET_ENV_PATTERNS


class InspectionError(Exception):
    def __init__(self, message: str, challenge: str = "", service: str = "", step: str = ""):
        self.challenge = challenge
        self.service = service
        self.step = step
        super().__init__(message)


ROOT_USERS = frozenset({"", "0", "root", "0:0", "root:root"})


def inspect_image_security(
    reference: str,
    docker: DockerCLI,
    *,
    challenge: str = "",
    service: str | None = None,
    require_exposed_port: bool = True,
    allow_flags: bool = False,
) -> list[str]:
    """Inspect image for security requirements. Returns list of errors."""
    errors: list[str] = []
    label = f"{challenge}/{service}" if service else challenge

    data = docker.inspect_image(reference)
    if not data:
        errors.append(f"{label}: image not found: {reference}")
        return errors

    config = data.get("Config", {})

    user = config.get("User", "")
    if user.lower() in ROOT_USERS or user == "":
        errors.append(f"{label}: image runs as root (User={user!r})")

    if require_exposed_port:
        exposed = config.get("ExposedPorts") or data.get("ContainerConfig", {}).get("ExposedPorts")
        if not exposed:
            errors.append(f"{label}: no exposed ports")

    for env_var in config.get("Env") or []:
        for pattern in SECRET_ENV_PATTERNS:
            if pattern.search(env_var):
                errors.append(f"{label}: suspicious env var pattern")
                break

    history = docker.image_history(reference)
    if history:
        if PRIVATE_KEY_PATTERN.search(history):
            errors.append(f"{label}: private key pattern in image history")
        for pattern in () if allow_flags else FLAG_PATTERNS:
            for match in pattern.finditer(history):
                if match.group(0).lower() not in ALLOWED_PLACEHOLDER_FLAGS:
                    errors.append(f"{label}: flag pattern in image history")

    errors.extend(_inspect_image_archive(reference, label, docker, allow_flags=allow_flags))

    return errors


def _inspect_image_archive(
    reference: str, label: str, docker: DockerCLI, *, allow_flags: bool = False
) -> list[str]:
    """Save and inspect image tar for forbidden content without dangerous extraction."""
    errors: list[str] = []
    archive = docker.save_image_bytes(reference)
    if not archive:
        return errors

    try:
        with tarfile.open(fileobj=BytesIO(archive), mode="r") as tar:
            for member in tar.getmembers():
                name = member.name.lower()
                if "solve.md" in name:
                    errors.append(f"{label}: solve.md found in image archive")
                if ".git/" in name or name.endswith("/.git"):
                    errors.append(f"{label}: .git found in image archive")
                if "id_rsa" in name or "private.key" in name or "private_key" in name:
                    errors.append(f"{label}: private key file in image archive")
                if member.isfile() and member.size < 1024 * 1024:
                    try:
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="replace")
                            if PRIVATE_KEY_PATTERN.search(content):
                                errors.append(f"{label}: private key in {member.name}")
                            for pattern in () if allow_flags else FLAG_PATTERNS:
                                for match in pattern.finditer(content):
                                    if match.group(0).lower() not in ALLOWED_PLACEHOLDER_FLAGS:
                                        errors.append(f"{label}: flag in {member.name}")
                    except Exception:
                        pass
    except Exception:
        pass

    return errors
