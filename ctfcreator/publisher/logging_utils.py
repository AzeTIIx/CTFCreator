"""Logging helpers with defensive redaction."""

from __future__ import annotations

import logging
import re
from pathlib import Path

_REDACT_PATTERNS = [
    re.compile(r"(?i)(password|secret|token|api_key|private_key)\s*=\s*\S+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"flag\{[^\}]+\}", re.IGNORECASE),
    re.compile(r"ctf\{[^\}]+\}", re.IGNORECASE),
    re.compile(r"affl\{[^\}]+\}", re.IGNORECASE),
]


def redact(text: str) -> str:
    """Redact sensitive patterns from log output."""
    result = text
    for pattern in _REDACT_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure module logger."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s", force=True)
    logger = logging.getLogger("publisher")
    for name in ("publisher.docker", "publisher.registry"):
        logging.getLogger(name).setLevel(level)
    return logger


def log_command(cmd: list[str]) -> str:
    """Format a command for safe logging."""
    return format_short_docker_cmd(cmd)


def format_short_docker_cmd(cmd: list[str], *, cwd: str | Path | None = None) -> str:
    """Human-readable docker command (no absolute exe path, shorter paths)."""
    if not cmd:
        return ""

    parts = list(cmd)
    exe = Path(parts[0])
    if exe.name.lower().startswith("docker"):
        parts[0] = "docker"

    cwd_path = Path(cwd).resolve() if cwd else None
    for index, token in enumerate(parts):
        if not token or token.startswith("-"):
            continue
        try:
            path = Path(token)
        except OSError:
            continue
        if not path.is_absolute() or len(token) <= 48:
            continue
        if cwd_path:
            try:
                rel = path.resolve().relative_to(cwd_path)
                parts[index] = rel.as_posix()
                continue
            except ValueError:
                pass
        parts[index] = path.name

    return redact(" ".join(parts))


def truncate_log_output(text: str, *, max_lines: int = 12, max_chars: int = 2000) -> str:
    """Keep log output bounded and safe."""
    cleaned = redact(text).strip()
    if not cleaned:
        return ""
    lines = cleaned.splitlines()
    if len(lines) > max_lines:
        head = lines[:max_lines]
        cleaned = "\n".join(head) + f"\n... ({len(lines) - max_lines} more lines)"
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + "..."
    return cleaned


def get_docker_logger() -> logging.Logger:
    return logging.getLogger("publisher.docker")


def get_registry_logger() -> logging.Logger:
    return logging.getLogger("publisher.registry")
