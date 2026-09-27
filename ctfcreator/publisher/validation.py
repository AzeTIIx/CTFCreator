"""Preflight validation and security checks."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .discovery import normalize_slug, normalize_service_name
from .models import (
    CTFD_COMPOSE_ALLOWED_KEYS,
    CTFD_SERVICE_ALLOWED_KEYS,
    DiscoveredChallenge,
    ChallengeType,
    FORBIDDEN_COMPOSE_KEYS,
    TEACHER_EXCLUDED,
)

# Patterns for security scanning — guardrails, not proof of absence
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
ENV_FILE_PATTERN = re.compile(r"^\.env($|\.)")
FLAG_PATTERNS = [
    re.compile(r"flag\{[a-zA-Z0-9_\-]{8,}\}", re.IGNORECASE),
    re.compile(r"ctf\{[a-zA-Z0-9_\-]{8,}\}", re.IGNORECASE),
    re.compile(r"affl\{[a-zA-Z0-9_\-]{8,}\}", re.IGNORECASE),
]
ALLOWED_PLACEHOLDER_FLAGS = frozenset({
    "flag{placeholder}",
    "flag{fake}",
    "flag{example}",
    "flag{test}",
    "flag{changeme}",
    "ctf{placeholder}",
    "ctf{fake}",
    "ctf{example}",
    "ctf{test}",
})
LATEST_PATTERN = re.compile(r":latest\b|/latest\b|\blatest:")
SECRET_ENV_PATTERNS = [
    re.compile(r"(?i)(password|secret|token|api_key|private_key)\s*="),
]
COPY_DOT_PATTERN = re.compile(r"^\s*COPY\s+\.\s", re.MULTILINE | re.IGNORECASE)
USER_PATTERN = re.compile(r"^\s*USER\s+", re.MULTILINE | re.IGNORECASE)

REQUIRED_DOCKERIGNORE_ENTRIES = {".git", "solve.md", "tests", "expected"}


class ValidationError(Exception):
    """Preflight validation failure."""

    def __init__(self, message: str, challenge: str = "", step: str = ""):
        self.challenge = challenge
        self.step = step
        super().__init__(message)


def validate_version(version: str) -> None:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", version):
        raise ValidationError(f"Invalid version syntax: {version!r}")


def validate_registry(registry: str) -> None:
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(?::[0-9]{1,5})?$", registry):
        raise ValidationError(f"Invalid registry host:port: {registry!r}")
    if any(c in registry for c in ";|&$`<>(){}[]!#"):
        raise ValidationError(f"Registry contains forbidden shell characters: {registry!r}")


def validate_shell_safe(value: str, name: str) -> None:
    forbidden = ";|&$`<>(){}[]!#\\'\n\r"
    for ch in forbidden:
        if ch in value:
            raise ValidationError(f"{name} contains forbidden character {ch!r}: {value!r}")


def compute_image_reference(registry: str, slug: str, version: str, service: str | None = None) -> str:
    """Compute deterministic registry image reference."""
    norm_slug = normalize_slug(slug)
    if service:
        norm_service = normalize_service_name(service)
        repo = f"{norm_slug}-{norm_service}"
    else:
        repo = norm_slug
    if version == "latest" or not version:
        raise ValidationError("Version must not be empty or 'latest'")
    return f"{registry}/{repo}:{version}"


def _dockerignore_regex(pattern: str) -> re.Pattern[str]:
    """Translate a .dockerignore pattern (moby patternmatcher semantics) to a regex.

    Patterns are anchored at the context root; ``*`` and ``?`` never cross ``/``;
    ``**`` matches any number of directories.
    """
    out = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 2] == "**":
                i += 2
                if pattern[i:i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape(c))
            else:
                out.append(pattern[i:j + 1])
                i = j
        elif c == "\\" and i + 1 < len(pattern):
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def load_dockerignore(context: Path) -> list[tuple[bool, re.Pattern[str]]]:
    """Parse ``context/.dockerignore`` into (is_exception, regex) rules, in order."""
    path = context / ".dockerignore"
    if not path.is_file():
        return []
    rules: list[tuple[bool, re.Pattern[str]]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        if negate:
            line = line[1:].strip()
        line = line.strip("/")
        line = "/".join(part for part in line.split("/") if part not in ("", "."))
        if not line:
            continue
        rules.append((negate, _dockerignore_regex(line)))
    return rules


def is_dockerignored(rel_path: str, rules: list[tuple[bool, re.Pattern[str]]]) -> bool:
    """True if ``rel_path`` (posix, relative to context) is excluded from the build context.

    A file is excluded when it, or one of its parent directories, matches a rule;
    the last matching rule wins (``!`` re-includes), as in ``docker build``.
    """
    parts = rel_path.split("/")
    candidates = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    excluded = False
    for negate, rx in rules:
        if any(rx.match(c) for c in candidates):
            excluded = not negate
    return excluded


def check_dockerignore(context: Path, challenge: str) -> list[str]:
    """Validate .dockerignore presence and minimum exclusions."""
    errors: list[str] = []
    dockerignore = context / ".dockerignore"
    if not dockerignore.is_file():
        errors.append(f"{challenge}: missing .dockerignore in {context}")
        return errors

    content = dockerignore.read_text(encoding="utf-8", errors="replace")
    lines = {line.strip().rstrip("/") for line in content.splitlines() if line.strip() and not line.strip().startswith("#")}

    for required in REQUIRED_DOCKERIGNORE_ENTRIES:
        found = any(required in line or line.endswith(required) for line in lines)
        if not found:
            errors.append(f"{challenge}: .dockerignore must exclude {required}")

    return errors


def scan_file_for_secrets(
    path: Path, *, allow_placeholders: bool = False, allow_flags: bool = False
) -> list[str]:
    """Scan a file for suspicious secret/flag patterns."""
    issues: list[str] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return issues

    if PRIVATE_KEY_PATTERN.search(content):
        issues.append(f"Private key pattern in {path}")

    for pattern in () if allow_flags else FLAG_PATTERNS:
        for match in pattern.finditer(content):
            matched = match.group(0).lower()
            if allow_placeholders and matched in ALLOWED_PLACEHOLDER_FLAGS:
                continue
            issues.append(f"Flag pattern in {path}: {match.group(0)[:20]}...")

    if path.name == ".env" or ENV_FILE_PATTERN.match(path.name):
        issues.append(f".env file in build context: {path}")

    return issues


def validate_dockerfile(path: Path, challenge: str, *, allow_flags: bool = False) -> list[str]:
    """Validate Dockerfile security requirements."""
    errors: list[str] = []
    content = path.read_text(encoding="utf-8", errors="replace")

    if not USER_PATTERN.search(content):
        errors.append(f"{challenge}: Dockerfile must contain USER directive (non-root)")

    if COPY_DOT_PATTERN.search(content):
        dockerignore = path.parent / ".dockerignore"
        if not dockerignore.is_file():
            errors.append(
                f"{challenge}: COPY . . without sufficient .dockerignore"
            )

    if LATEST_PATTERN.search(content):
        errors.append(f"{challenge}: Dockerfile must not reference 'latest'")

    errors.extend(scan_file_for_secrets(path, allow_placeholders=True, allow_flags=allow_flags))
    return errors


def validate_compose_security(compose_path: Path, challenge: str, *, allow_flags: bool = False) -> list[str]:
    """Validate compose file for forbidden runtime configurations."""
    errors: list[str] = []
    with compose_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not data:
        return errors

    services = data.get("services", {})
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if svc.get("privileged"):
            errors.append(f"{challenge}/{svc_name}: privileged not allowed")
        if svc.get("network_mode") == "host":
            errors.append(f"{challenge}/{svc_name}: host network not allowed")
        if "volumes" in svc:
            for vol in svc.get("volumes", []):
                vol_str = str(vol)
                if "/var/run/docker.sock" in vol_str:
                    errors.append(f"{challenge}/{svc_name}: docker socket mount not allowed")
                if re.match(r"^[./~]", vol_str.split(":")[0]):
                    errors.append(f"{challenge}/{svc_name}: host volume mount not allowed: {vol_str}")

        image = svc.get("image", "")
        if isinstance(image, str) and LATEST_PATTERN.search(image):
            errors.append(f"{challenge}/{svc_name}: must not use 'latest' tag")

    content = compose_path.read_text(encoding="utf-8", errors="replace")
    errors.extend(scan_file_for_secrets(compose_path, allow_flags=allow_flags))
    return errors


def validate_ctfd_override(path: Path, challenge: str) -> list[str]:
    """Validate optional docker-compose.ctfd.yml override."""
    errors: list[str] = []
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not data:
        return errors

    for key in data:
        if key not in CTFD_COMPOSE_ALLOWED_KEYS:
            errors.append(f"{challenge}: forbidden top-level key in ctfd override: {key}")

    services = data.get("services", {})
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if "build" in svc:
            errors.append(f"{challenge}/{svc_name}: build: not allowed in ctfd override")
        for key in svc:
            if key not in CTFD_SERVICE_ALLOWED_KEYS:
                errors.append(f"{challenge}/{svc_name}: forbidden key in ctfd override: {key}")

    return errors


def validate_challenge_preflight(
    challenge: DiscoveredChallenge, *, allow_static_flags: bool = False
) -> list[str]:
    """Run all preflight validations for a challenge.

    ``allow_static_flags`` disables only the flag-pattern checks (flags baked into
    the image on purpose); private keys, .env files and the rest stay fail-closed.
    """
    if challenge.challenge_type == ChallengeType.INVALID:
        return list(challenge.errors)

    if challenge.challenge_type == ChallengeType.STATIC:
        return []

    errors: list[str] = list(challenge.errors)

    if challenge.challenge_type == ChallengeType.SINGLE_IMAGE:
        assert challenge.dockerfile is not None
        errors.extend(check_dockerignore(challenge.path, challenge.slug))
        errors.extend(validate_dockerfile(challenge.dockerfile, challenge.slug, allow_flags=allow_static_flags))
        # Scan only what `docker build` actually sends: files excluded by
        # .dockerignore (README, challenge.yml, teacher scripts...) never reach the image.
        ignore_rules = load_dockerignore(challenge.path)
        for f in challenge.path.rglob("*"):
            if f.is_file() and f.name not in TEACHER_EXCLUDED:
                if f.name == "solve.md" or f == challenge.dockerfile:
                    continue
                rel = f.relative_to(challenge.path)
                if "tests" in rel.parts or "expected" in rel.parts:
                    continue
                if is_dockerignored(rel.as_posix(), ignore_rules):
                    continue
                errors.extend(scan_file_for_secrets(f, allow_flags=allow_static_flags))

    elif challenge.challenge_type == ChallengeType.MULTI_SERVICE:
        assert challenge.compose_file is not None
        errors.extend(validate_compose_security(challenge.compose_file, challenge.slug, allow_flags=allow_static_flags))
        if challenge.ctfd_override:
            errors.extend(validate_ctfd_override(challenge.ctfd_override, challenge.slug))

        import yaml
        with challenge.compose_file.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        for svc_name, svc in data.get("services", {}).items():
            if not isinstance(svc, dict):
                continue
            build = svc.get("build")
            if build:
                if isinstance(build, str):
                    ctx = challenge.path / build
                    df = ctx / "Dockerfile"
                elif isinstance(build, dict):
                    ctx_path = build.get("context", ".")
                    ctx = challenge.path / ctx_path if not Path(ctx_path).is_absolute() else Path(ctx_path)
                    df_name = build.get("dockerfile", "Dockerfile")
                    df = ctx / df_name
                else:
                    continue
                errors.extend(check_dockerignore(ctx, f"{challenge.slug}/{svc_name}"))
                if df.is_file():
                    errors.extend(validate_dockerfile(df, f"{challenge.slug}/{svc_name}", allow_flags=allow_static_flags))

    return errors
