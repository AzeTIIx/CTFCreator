"""Challenge discovery and classification."""

from __future__ import annotations

import re
from pathlib import Path

from .models import (
    COMPOSE_HISTORICAL_ALIAS,
    COMPOSE_SOURCE_FILES,
    ChallengeType,
    DiscoveredChallenge,
)

IGNORED_DIRS = frozenset({
    "dist",
    "scripts",
    "tests",
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
})


def normalize_slug(name: str) -> str:
    """Normalize a directory name to a Docker-compatible repository component."""
    normalized = name.lower().replace("_", "-")
    normalized = re.sub(r"[^a-z0-9._-]+", "-", normalized)
    normalized = re.sub(r"-+", "-", normalized)
    normalized = normalized.strip("-.")
    if not normalized:
        raise ValueError(f"Cannot normalize slug from '{name}'")
    if len(normalized) > 128:
        normalized = normalized[:128].rstrip("-.")
    return normalized


def normalize_service_name(name: str) -> str:
    """Normalize a compose service name."""
    return normalize_slug(name)


def is_hidden(name: str) -> bool:
    return name.startswith((".", "_"))


def find_compose_file(challenge_dir: Path) -> tuple[Path | None, list[str]]:
    """Find compose source file with priority order."""
    warnings: list[str] = []
    for filename in COMPOSE_SOURCE_FILES:
        candidate = challenge_dir / filename
        if candidate.is_file():
            return candidate, warnings

    alias = challenge_dir / COMPOSE_HISTORICAL_ALIAS
    if alias.is_file():
        warnings.append(
            f"{COMPOSE_HISTORICAL_ALIAS} is a historical alias; "
            "migrate to docker-compose.yml"
        )
        return alias, warnings

    return None, warnings


def has_build_directive(compose_file: Path) -> bool:
    """Check if compose file contains at least one build: directive."""
    import yaml

    with compose_file.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not data or "services" not in data:
        return False
    for svc in data["services"].values():
        if isinstance(svc, dict) and "build" in svc:
            return True
    return False


def list_static_artifacts(challenge_dir: Path) -> list[str]:
    """List distributable static artifacts, excluding teacher-only files."""
    artifacts: list[str] = []
    excluded_names = {"solve.md", ".git", "tests", "expected"}

    for item in sorted(challenge_dir.rglob("*")):
        if not item.is_file():
            continue
        rel = item.relative_to(challenge_dir)
        parts = rel.parts
        if any(p in excluded_names or p.startswith(".") for p in parts):
            continue
        if "solve.md" in parts:
            continue
        artifacts.append(str(rel).replace("\\", "/"))
    return artifacts


def classify_challenge(challenge_dir: Path) -> DiscoveredChallenge:
    """Classify a single challenge directory."""
    slug = challenge_dir.name
    has_readme = (challenge_dir / "README.md").is_file()
    has_solve = (challenge_dir / "solve.md").is_file()
    has_dockerfile = (challenge_dir / "Dockerfile").is_file()
    compose_file, compose_warnings = find_compose_file(challenge_dir)
    ctfd_override = challenge_dir / "docker-compose.ctfd.yml"
    ctfd_override_path = ctfd_override if ctfd_override.is_file() else None

    errors: list[str] = []
    warnings = list(compose_warnings)

    if not has_readme:
        errors.append("Missing required README.md")
    if not has_solve:
        errors.append("Missing required solve.md")

    if compose_file is not None:
        if not has_build_directive(compose_file):
            errors.append(
                f"Compose file {compose_file.name} has no service with build: directive"
            )
        if errors:
            return DiscoveredChallenge(
                slug=slug,
                path=challenge_dir,
                challenge_type=ChallengeType.INVALID,
                compose_file=compose_file,
                ctfd_override=ctfd_override_path,
                errors=errors,
                warnings=warnings,
            )
        return DiscoveredChallenge(
            slug=slug,
            path=challenge_dir,
            challenge_type=ChallengeType.MULTI_SERVICE,
            compose_file=compose_file,
            ctfd_override=ctfd_override_path,
            warnings=warnings,
        )

    if has_dockerfile:
        if errors:
            return DiscoveredChallenge(
                slug=slug,
                path=challenge_dir,
                challenge_type=ChallengeType.INVALID,
                dockerfile=challenge_dir / "Dockerfile",
                errors=errors,
                warnings=warnings,
            )
        return DiscoveredChallenge(
            slug=slug,
            path=challenge_dir,
            challenge_type=ChallengeType.SINGLE_IMAGE,
            dockerfile=challenge_dir / "Dockerfile",
            warnings=warnings,
        )

    # Static: has readme and solve, no docker
    if has_readme and has_solve and not has_dockerfile:
        return DiscoveredChallenge(
            slug=slug,
            path=challenge_dir,
            challenge_type=ChallengeType.STATIC,
            warnings=warnings,
        )

    # Invalid
    if not errors:
        if not has_dockerfile:
            errors.append("No Dockerfile or recognized compose file found")
    return DiscoveredChallenge(
        slug=slug,
        path=challenge_dir,
        challenge_type=ChallengeType.INVALID,
        errors=errors,
        warnings=warnings,
    )


def discover_challenges(
    root: Path,
    *,
    filter_slugs: list[str] | None = None,
) -> list[DiscoveredChallenge]:
    """Discover all challenges under root directory."""
    if not root.is_dir():
        raise FileNotFoundError(f"Root directory does not exist: {root}")

    challenges: list[DiscoveredChallenge] = []
    normalized_filters = {normalize_slug(s) for s in filter_slugs} if filter_slugs else None

    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        if is_hidden(entry.name) or entry.name in IGNORED_DIRS:
            continue

        discovered = classify_challenge(entry)
        if normalized_filters is not None:
            try:
                norm = normalize_slug(entry.name)
            except ValueError:
                norm = entry.name
            if norm not in normalized_filters and entry.name not in filter_slugs:
                continue

        challenges.append(discovered)

    return challenges


def detect_slug_collisions(challenges: list[DiscoveredChallenge]) -> list[str]:
    """Detect slug normalization collisions."""
    seen: dict[str, str] = {}
    collisions: list[str] = []
    for ch in challenges:
        try:
            norm = normalize_slug(ch.slug)
        except ValueError:
            continue
        if norm in seen and seen[norm] != ch.slug:
            collisions.append(
                f"Normalization collision: '{seen[norm]}' and '{ch.slug}' -> '{norm}'"
            )
        seen[norm] = ch.slug
    return collisions
