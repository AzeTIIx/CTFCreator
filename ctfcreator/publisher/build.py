"""Image build operations."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .discovery import normalize_slug, normalize_service_name
from .docker_cli import DockerCLI
from .models import DiscoveredChallenge, PublishConfig, ServiceBuildInfo
from .validation import compute_image_reference


class BuildError(Exception):
    def __init__(self, message: str, challenge: str = "", service: str = "", step: str = ""):
        self.challenge = challenge
        self.service = service
        self.step = step
        super().__init__(message)


def build_single_image(
    challenge: DiscoveredChallenge,
    config: PublishConfig,
    docker: DockerCLI,
) -> str:
    """Build a single-container challenge image. Returns local reference."""
    reference = compute_image_reference(config.registry, challenge.slug, config.version)
    local_ref = reference  # tag directly to target

    if config.dry_run:
        return local_ref

    args = ["build", "-t", local_ref, str(challenge.path)]
    if config.pull:
        args.insert(1, "--pull")
    if config.no_cache:
        args.insert(1, "--no-cache")

    result = docker.docker(*args)
    if result.returncode != 0:
        raise BuildError(
            f"Build failed: {result.stderr[:500]}",
            challenge=challenge.slug,
            step="docker-build",
        )
    return local_ref


def parse_compose_config(
    compose_file: Path,
    challenge_dir: Path,
    docker: DockerCLI,
) -> dict:
    """Get normalized compose config via docker compose config."""
    try:
        result = docker.compose(str(compose_file), "config", "--format", "json", cwd=str(challenge_dir))
        if result.returncode == 0 and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        pass

    # Fallback: parse YAML and normalize manually
    with compose_file.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return _normalize_compose_yaml(data, challenge_dir)


def _normalize_compose_yaml(data: dict, challenge_dir: Path) -> dict:
    """Fallback normalization when docker compose config --format json unavailable."""
    services = {}
    for name, svc in data.get("services", {}).items():
        if not isinstance(svc, dict):
            continue
        normalized = dict(svc)
        build = svc.get("build")
        if build:
            if isinstance(build, str):
                normalized["build"] = {"context": str(challenge_dir / build)}
            elif isinstance(build, dict):
                ctx = build.get("context", ".")
                ctx_path = challenge_dir / ctx if not Path(ctx).is_absolute() else Path(ctx)
                normalized["build"] = {
                    "context": str(ctx_path.resolve()),
                    "dockerfile": build.get("dockerfile", "Dockerfile"),
                }
        if "image" in svc:
            normalized["image"] = svc["image"]
        services[name] = normalized
    return {"services": services}


def resolve_compose_services(
    challenge: DiscoveredChallenge,
    config: PublishConfig,
    docker: DockerCLI,
) -> list[ServiceBuildInfo]:
    """Resolve all services from compose with build/external classification."""
    assert challenge.compose_file is not None
    compose_config = parse_compose_config(challenge.compose_file, challenge.path, docker)
    services: list[ServiceBuildInfo] = []
    norm_slug = normalize_slug(challenge.slug)

    for svc_name, svc in compose_config.get("services", {}).items():
        if not isinstance(svc, dict):
            continue

        has_build = "build" in svc
        source_image = svc.get("image")

        if has_build:
            registry_ref = compute_image_reference(
                config.registry, challenge.slug, config.version, svc_name
            )
            if source_image:
                local_image = source_image
            else:
                local_image = f"{norm_slug}-{normalize_service_name(svc_name)}:local-build"

            build_info = svc["build"]
            if isinstance(build_info, str):
                context = Path(build_info)
                dockerfile = "Dockerfile"
            else:
                context = Path(build_info.get("context", "."))
                dockerfile = build_info.get("dockerfile", "Dockerfile")

            services.append(ServiceBuildInfo(
                name=svc_name,
                context=context,
                dockerfile=dockerfile,
                source_image=source_image,
                local_image=local_image,
                registry_reference=registry_ref,
                is_external=False,
                built=True,
            ))
        elif source_image:
            services.append(ServiceBuildInfo(
                name=svc_name,
                context=challenge.path,
                dockerfile=None,
                source_image=source_image,
                local_image=source_image,
                registry_reference=source_image,
                is_external=True,
                built=False,
            ))

    return services


def build_compose_images(
    challenge: DiscoveredChallenge,
    config: PublishConfig,
    docker: DockerCLI,
) -> list[ServiceBuildInfo]:
    """Build compose services and retag to registry references."""
    assert challenge.compose_file is not None
    services = resolve_compose_services(challenge, config, docker)

    if config.dry_run:
        return services

    build_services = [s for s in services if s.built]
    if build_services:
        compose_args: list[str] = ["build"]
        if config.pull:
            compose_args.append("--pull")
        if config.no_cache:
            compose_args.append("--no-cache")
        result = docker.compose(
            str(challenge.compose_file),
            *compose_args,
            cwd=str(challenge.path),
            timeout=600,
        )
        if result.returncode != 0:
            raise BuildError(
                f"Compose build failed: {result.stderr[:500]}",
                challenge=challenge.slug,
                step="compose-build",
            )

    # Retag built images
    for svc in build_services:
        # Find actual built image ID
        actual_image = _find_built_image(svc, challenge, docker)
        if actual_image and actual_image != svc.registry_reference:
            result = docker.docker("tag", actual_image, svc.registry_reference)
            if result.returncode != 0:
                raise BuildError(
                    f"Retag failed for {svc.name}: {result.stderr}",
                    challenge=challenge.slug,
                    service=svc.name,
                    step="docker-tag",
                )
        svc.local_image = svc.registry_reference

    return services


def _find_built_image(
    svc: ServiceBuildInfo,
    challenge: DiscoveredChallenge,
    docker: DockerCLI,
) -> str | None:
    """Find the locally built image for a service."""
    candidates = [svc.local_image, svc.registry_reference]
    if svc.source_image:
        candidates.insert(0, svc.source_image)

    for ref in candidates:
        inspect = docker.inspect_image(ref)
        if inspect:
            return ref

    # Try compose-implied name
    norm_slug = normalize_slug(challenge.slug)
    implied = f"{norm_slug}-{normalize_service_name(svc.name)}"
    for ref in [f"{implied}:latest", f"{implied}:local-build"]:
        inspect = docker.inspect_image(ref)
        if inspect:
            return ref

    return svc.local_image
