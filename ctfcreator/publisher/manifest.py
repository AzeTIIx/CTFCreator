"""Generate CTFd-compatible compose artifacts and publication manifests."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .discovery import list_static_artifacts, normalize_slug, normalize_service_name
from .models import (
    CTFD_COMPOSE_ALLOWED_KEYS,
    CTFD_SERVICE_ALLOWED_KEYS,
    ChallengeResult,
    ChallengeStatus,
    ChallengeType,
    DiscoveredChallenge,
    OverallStatus,
    PublicationManifest,
    PublishConfig,
    ServiceBuildInfo,
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_ctfd_compose(
    challenge: DiscoveredChallenge,
    services: list[ServiceBuildInfo],
    compose_config: dict,
    config: PublishConfig,
) -> dict:
    """Generate CTFd plugin-compatible compose from normalized config."""
    ctfd_services: dict = {}

    service_refs = {s.name: s for s in services}

    for svc_name, svc in compose_config.get("services", {}).items():
        if not isinstance(svc, dict):
            continue

        info = service_refs.get(svc_name)
        if info and info.is_external:
            image_ref = info.source_image or info.registry_reference
        elif info:
            image_ref = info.registry_reference
        else:
            image_ref = svc.get("image", "")

        ctfd_svc: dict = {"image": image_ref}

        for key in CTFD_SERVICE_ALLOWED_KEYS:
            if key == "image":
                continue
            if key in svc:
                ctfd_svc[key] = svc[key]

        # Strip forbidden keys from source; fail only on keys that affect runtime and aren't stripped
        critical_fail = {"volumes", "privileged", "network_mode", "devices"}
        for key in svc:
            if key in critical_fail:
                raise ValueError(
                    f"Service {svc_name} has forbidden key '{key}' required for execution"
                )

        ctfd_services[svc_name] = ctfd_svc

    return {"services": ctfd_services}


def write_ctfd_compose(
    challenge: DiscoveredChallenge,
    compose_data: dict,
    config: PublishConfig,
) -> Path:
    """Write generated compose artifact to output directory."""
    compose_dir = config.output_dir / "compose"
    compose_dir.mkdir(parents=True, exist_ok=True)
    out_path = compose_dir / f"{normalize_slug(challenge.slug)}.yml"

    # Validate output has no build:
    content = yaml.dump(compose_data, default_flow_style=False, sort_keys=True)
    if "build:" in content:
        raise ValueError("Generated compose must not contain build:")

    out_path.write_text(content, encoding="utf-8")
    return out_path


def apply_ctfd_override(
    override_path: Path,
    services: list[ServiceBuildInfo],
    config: PublishConfig,
    challenge: DiscoveredChallenge,
) -> dict:
    """Apply optional ctfd override with registry image references."""
    with override_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    service_refs = {s.name: s for s in services if not s.is_external}
    external_refs = {s.name: s for s in services if s.is_external}

    for svc_name, svc in data.get("services", {}).items():
        if not isinstance(svc, dict):
            continue
        if svc_name in service_refs:
            svc["image"] = service_refs[svc_name].registry_reference
        elif svc_name in external_refs:
            svc["image"] = external_refs[svc_name].source_image

    return data


def slug_to_env_var(slug: str, service: str | None = None) -> str:
    """Convert slug/service to ENV variable name."""
    parts = [normalize_slug(slug).upper().replace("-", "_")]
    if service:
        parts.append(normalize_service_name(service).upper().replace("-", "_"))
    return "_".join(parts) + "_IMAGE"


def write_manifest_atomic(manifest: PublicationManifest, config: PublishConfig) -> None:
    """Write manifest files atomically."""
    config.output_dir.mkdir(parents=True, exist_ok=True)

    manifest_data = manifest.to_dict()
    report_md = generate_report_md(manifest)
    env_content = generate_env_file(manifest)

    files = {
        "publication-manifest.json": json.dumps(manifest_data, indent=2, ensure_ascii=False),
        "publication-report.md": report_md,
        "ctfd-images.env": env_content,
    }

    for filename, content in files.items():
        _atomic_write(config.output_dir / filename, content)


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp + replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def generate_env_file(manifest: PublicationManifest) -> str:
    """Generate ctfd-images.env content."""
    lines: list[str] = []
    for ch in manifest.challenges:
        for img in ch.images:
            var = slug_to_env_var(ch.slug, img.service)
            lines.append(f"{var}={img.reference}")
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def generate_report_md(manifest: PublicationManifest) -> str:
    """Generate human-readable publication report."""
    lines = [
        "# Publication Report",
        "",
        f"- **Registry**: {manifest.registry}",
        f"- **Version**: {manifest.version}",
        f"- **Started**: {manifest.started_at}",
        f"- **Completed**: {manifest.completed_at}",
        f"- **Status**: {manifest.overall_status.value}",
        "",
        "## Challenges",
        "",
    ]

    for ch in manifest.challenges:
        lines.append(f"### {ch.slug} ({ch.type.value})")
        lines.append(f"- Status: {ch.status.value}")
        if ch.images:
            lines.append("- Images:")
            for img in ch.images:
                verified = "verified" if img.verified else "NOT verified"
                digest = img.digest or "n/a"
                svc = f" ({img.service})" if img.service else ""
                lines.append(f"  - `{img.reference}`{svc}: {digest} [{verified}]")
        if ch.generated_ctfd_compose:
            lines.append(f"- Generated compose: `{ch.generated_ctfd_compose}`")
        if ch.static_artifacts:
            lines.append(f"- Static artifacts: {len(ch.static_artifacts)} files")
        if ch.external_dependencies:
            lines.append("- External dependencies:")
            for dep in ch.external_dependencies:
                lines.append(f"  - `{dep}`")
        if ch.warnings:
            lines.append("- Warnings:")
            for w in ch.warnings:
                lines.append(f"  - {w}")
        if ch.errors:
            lines.append("- Errors:")
            for e in ch.errors:
                lines.append(f"  - {e}")
        lines.append("")

    return "\n".join(lines)


def build_challenge_result_static(challenge: DiscoveredChallenge) -> ChallengeResult:
    """Build result for static challenge."""
    artifacts = list_static_artifacts(challenge.path)
    return ChallengeResult(
        slug=challenge.slug,
        path=str(challenge.path.name),
        type=ChallengeType.STATIC,
        status=ChallengeStatus.SKIPPED_STATIC,
        static_artifacts=artifacts,
        warnings=challenge.warnings,
    )
