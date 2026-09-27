"""Data models and constants for the challenge publisher."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Exit codes (section 13)
EXIT_SUCCESS = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_DOCKER = 4
EXIT_REGISTRY = 5
EXIT_BUILD = 6
EXIT_SECURITY = 7
EXIT_PUSH = 8
EXIT_VERIFY = 9
EXIT_PARTIAL = 10

COMPOSE_SOURCE_FILES = [
    "docker-compose.yml",
    "compose.yml",
    "docker-compose.yaml",
    "compose.yaml",
]
COMPOSE_HISTORICAL_ALIAS = "docker-compose.build.yml"

CTFD_COMPOSE_ALLOWED_KEYS = frozenset({"services"})
CTFD_SERVICE_ALLOWED_KEYS = frozenset({
    "image",
    "ports",
    "environment",
    "depends_on",
    "command",
    "entrypoint",
    "mem_limit",
    "cpus",
    "pids_limit",
    "cap_drop",
    "read_only",
})
FORBIDDEN_COMPOSE_KEYS = frozenset({
    "build",
    "volumes",
    "privileged",
    "network_mode",
    "devices",
})
TEACHER_EXCLUDED = frozenset({"solve.md", ".git", "tests", "expected"})


class ChallengeType(str, Enum):
    STATIC = "static"
    SINGLE_IMAGE = "single-image"
    MULTI_SERVICE = "multi-service"
    INVALID = "invalid"


class ChallengeStatus(str, Enum):
    PUBLISHED = "published"
    FAILED = "failed"
    SKIPPED_STATIC = "skipped-static"
    DRY_RUN = "dry-run"


class OverallStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    DRY_RUN = "dry-run"
    INTERRUPTED = "interrupted"


@dataclass
class PublishConfig:
    root: Path
    registry: str
    version: str
    registry_name: str = "ctfd-registry"
    registry_image: str = "registry:2"
    registry_volume: str = "ctfd-registry-data"
    bind_address: str = "127.0.0.1"
    registry_port: int = 5000
    no_create_registry: bool = False
    pull: bool = False
    no_cache: bool = False
    dry_run: bool = False
    challenges: list[str] | None = None
    continue_on_error: bool = False
    force: bool = False
    output_dir: Path = field(default_factory=lambda: Path("dist/publication"))
    json_output: bool = False
    verbose: bool = False
    allow_non_loopback_registry: bool = False
    allow_static_flags: bool = False


@dataclass
class DiscoveredChallenge:
    slug: str
    path: Path
    challenge_type: ChallengeType
    dockerfile: Path | None = None
    compose_file: Path | None = None
    ctfd_override: Path | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ServiceBuildInfo:
    name: str
    context: Path
    dockerfile: str | None
    source_image: str | None
    local_image: str
    registry_reference: str
    is_external: bool = False
    built: bool = True


@dataclass
class ImagePublication:
    service: str | None = None
    reference: str = ""
    digest: str | None = None
    local_digest: str | None = None
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "reference": self.reference,
            "digest": self.digest,
            "verified": self.verified,
        }


@dataclass
class ChallengeResult:
    slug: str
    path: str
    type: ChallengeType
    status: ChallengeStatus
    images: list[ImagePublication] = field(default_factory=list)
    generated_ctfd_compose: str | None = None
    static_artifacts: list[str] = field(default_factory=list)
    external_dependencies: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "path": self.path,
            "type": self.type.value,
            "status": self.status.value,
            "images": [img.to_dict() for img in self.images],
            "generated_ctfd_compose": self.generated_ctfd_compose,
            "static_artifacts": self.static_artifacts,
            "external_dependencies": self.external_dependencies,
            "warnings": self.warnings,
            "errors": self.errors,
        }


@dataclass
class PublicationManifest:
    schema_version: int = 1
    registry: str = ""
    version: str = ""
    started_at: str = ""
    completed_at: str = ""
    overall_status: OverallStatus = OverallStatus.FAILED
    challenges: list[ChallengeResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "registry": self.registry,
            "version": self.version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "overall_status": self.overall_status.value,
            "challenges": [ch.to_dict() for ch in self.challenges],
        }
