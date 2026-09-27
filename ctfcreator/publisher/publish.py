"""Push images and verify remote publication."""

from __future__ import annotations

import re

from .docker_cli import DockerCLI
from .inspect_image import inspect_image_security
from .logging_utils import get_docker_logger
from .models import ImagePublication, PublishConfig
from .registry import RegistryClient, check_immutability


class PushError(Exception):
    def __init__(self, message: str, challenge: str = "", service: str = "", step: str = ""):
        self.challenge = challenge
        self.service = service
        self.step = step
        super().__init__(message)


class VerifyError(Exception):
    def __init__(self, message: str, challenge: str = "", service: str = "", step: str = ""):
        self.challenge = challenge
        self.service = service
        self.step = step
        super().__init__(message)


def parse_reference(reference: str) -> tuple[str, str, str]:
    """Parse registry/repo:tag into (registry, repository, tag)."""
    if "/" not in reference:
        raise ValueError(f"Invalid reference: {reference}")
    registry, rest = reference.split("/", 1)
    if ":" not in rest:
        raise ValueError(f"Invalid reference (no tag): {reference}")
    repo, tag = rest.rsplit(":", 1)
    return registry, repo, tag


def verify_remote_publication(
    reference: str,
    config: PublishConfig,
    docker: DockerCLI,
    registry_client: RegistryClient,
    *,
    challenge: str = "",
    service: str | None = None,
    quiet: bool = False,
) -> ImagePublication | None:
    """Reuse an existing remote tag when present and not forcing republication."""
    if config.force:
        return None

    log = get_docker_logger()
    label = f"{challenge}/{service}" if service else challenge

    registry, repository, tag = parse_reference(reference)
    remote_digest = registry_client.get_tag_digest(repository, tag)
    if not remote_digest:
        return None

    pull = docker.docker("pull", reference, quiet=True)
    if pull.returncode != 0:
        return None

    inspect = docker.inspect_image(reference)
    if not inspect:
        return None

    pub = ImagePublication(
        service=service,
        reference=reference,
        digest=remote_digest,
        verified=True,
    )
    repo_digests = inspect.get("RepoDigests") or []
    if repo_digests:
        pub.digest = repo_digests[0].split("@")[-1] if "@" in repo_digests[0] else repo_digests[0]

    if quiet:
        log.debug("[%s] reusing remote tag: %s", label, reference)
    else:
        log.info("[%s] already published: %s", label, reference)
    return pub


def publish_image(
    reference: str,
    config: PublishConfig,
    docker: DockerCLI,
    registry_client: RegistryClient,
    *,
    challenge: str = "",
    service: str | None = None,
    skip_inspection: bool = False,
) -> ImagePublication:
    """Build pipeline: inspect, immutability check, push, verify."""
    pub = ImagePublication(service=service, reference=reference)
    log = get_docker_logger()
    label = f"{challenge}/{service}" if service else (challenge or reference)

    if config.dry_run:
        pub.verified = False
        return pub

    log.debug("[%s] pre-push inspection", label)
    if not skip_inspection:
        errors = inspect_image_security(
            reference, docker, challenge=challenge, service=service,
            allow_flags=config.allow_static_flags,
        )
        if errors:
            raise PushError(
                "; ".join(errors),
                challenge=challenge,
                service=service or "",
                step="pre-push-inspection",
            )

    local_digest = docker.image_digest(reference)
    pub.local_digest = local_digest

    registry, repository, tag = parse_reference(reference)

    # Immutability check
    if local_digest:
        action, is_idempotent, remote_digest = check_immutability(
            registry_client,
            repository,
            tag,
            local_digest,
            docker=docker,
            local_reference=reference,
            force=config.force,
        )
        if action == "block":
            raise PushError(
                f"Tag {reference} exists with different content "
                f"(remote manifest={remote_digest}, local config={local_digest}). Use --force to override.",
                challenge=challenge,
                service=service or "",
                step="immutability-check",
            )
        if action == "skip" and is_idempotent:
            pub.digest = remote_digest or local_digest
            pub.verified = True
            log.info("[%s] unchanged: %s", label, reference)
            return pub

    # Push (streamed to terminal)
    result = docker.docker("push", reference)
    if result.returncode != 0:
        raise PushError(
            f"Push failed: {result.stderr[:500]}",
            challenge=challenge,
            service=service or "",
            step="docker-push",
        )

    # Verify via registry API
    remote_digest = registry_client.get_tag_digest(repository, tag)
    if not remote_digest:
        raise VerifyError(
            f"Tag not found in registry after push: {reference}",
            challenge=challenge,
            service=service or "",
            step="registry-verify",
        )

    pull_result = docker.docker("pull", reference, quiet=True)
    if pull_result.returncode != 0:
        raise VerifyError(
            f"docker pull verification failed: {pull_result.stderr[:500]}",
            challenge=challenge,
            service=service or "",
            step="pull-verify",
        )

    inspect = docker.inspect_image(reference)
    if inspect:
        repo_digests = inspect.get("RepoDigests", [])
        if repo_digests:
            pub.digest = repo_digests[0].split("@")[-1] if "@" in repo_digests[0] else repo_digests[0]
        else:
            pub.digest = remote_digest
    else:
        pub.digest = remote_digest

    pub.verified = True
    log.info("[%s] published and verified: %s (%s)", label, reference, pub.digest)
    return pub


def detect_reference_collisions(references: list[tuple[str, str, str]]) -> list[str]:
    """
    Detect collisions where different sources map to same target.
    Input: list of (challenge, service, reference)
    """
    seen: dict[str, tuple[str, str]] = {}
    collisions: list[str] = []
    for challenge, service, ref in references:
        if ref in seen:
            prev = seen[ref]
            collisions.append(
                f"Collision: {prev[0]}/{prev[1]} and {challenge}/{service} -> {ref}"
            )
        seen[ref] = (challenge, service)
    return collisions
