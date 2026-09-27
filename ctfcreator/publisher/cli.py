"""CLI argument parsing and orchestration."""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

from .build import (
    BuildError,
    build_compose_images,
    build_single_image,
    parse_compose_config,
    resolve_compose_services,
)
from .discovery import (
    detect_slug_collisions,
    discover_challenges,
    normalize_slug,
)
from .docker_cli import DockerCLI, DockerNotFoundError, LoggingSubprocessRunner, SubprocessRunner
from .display import print_discovery_table, print_header, print_summary
from .logging_utils import log_command, setup_logging
from .manifest import (
    _utcnow_iso,
    apply_ctfd_override,
    build_challenge_result_static,
    generate_ctfd_compose,
    write_ctfd_compose,
    write_manifest_atomic,
)
from .models import (
    EXIT_BUILD,
    EXIT_DOCKER,
    EXIT_PARTIAL,
    EXIT_PREFLIGHT,
    EXIT_PUSH,
    EXIT_REGISTRY,
    EXIT_SECURITY,
    EXIT_SUCCESS,
    EXIT_USAGE,
    EXIT_VERIFY,
    ChallengeResult,
    ChallengeStatus,
    ChallengeType,
    OverallStatus,
    PublicationManifest,
    PublishConfig,
)
from .publish import (
    PushError,
    VerifyError,
    detect_reference_collisions,
    publish_image,
    verify_remote_publication,
)
from .registry import RegistryClient, RegistryError, ensure_registry
from .validation import ValidationError, compute_image_reference, validate_challenge_preflight, validate_registry, validate_shell_safe, validate_version


_interrupted = False


def _signal_handler(signum, frame):
    global _interrupted
    _interrupted = True


def read_version_from_file(root: Path) -> str | None:
    version_file = root / "VERSION"
    if version_file.is_file():
        version = version_file.read_text(encoding="utf-8").strip()
        try:
            validate_version(version)
            return version
        except ValidationError:
            return None
    return None


def parse_args(argv: list[str] | None = None) -> PublishConfig:
    parser = argparse.ArgumentParser(
        description="Auto-publish CTFd challenge Docker images to a local registry.",
        epilog=(
            "Examples:\n"
            "  python3 scripts/publish_challenges.py ./challenges --version 2026.1 --dry-run\n"
            "  python3 scripts/publish_challenges.py ./challenges --version 2026.1 --no-cache\n"
            "  python3 scripts/publish_challenges.py ./challenges --version 2026.1 --challenge web-idor"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("root", type=Path, help="Root directory containing challenge folders")
    parser.add_argument("--registry", default="localhost:5000", help="Registry host:port (default: localhost:5000)")
    parser.add_argument("--version", default=None, help="Publication version tag (required unless VERSION file exists)")
    parser.add_argument("--registry-name", default="ctfd-registry", help="Docker container name for registry")
    parser.add_argument("--registry-image", default="registry:2", help="Docker image for registry")
    parser.add_argument("--registry-volume", default="ctfd-registry-data", help="Docker volume for registry data")
    parser.add_argument("--bind-address", default="127.0.0.1", help="Registry bind address")
    parser.add_argument("--registry-port", type=int, default=5000, help="Registry port")
    parser.add_argument("--no-create-registry", action="store_true", help="Fail if registry does not exist")
    parser.add_argument("--pull", action="store_true", help="Pull base images during build")
    parser.add_argument("--no-cache", action="store_true", help="Build without cache")
    parser.add_argument("--dry-run", action="store_true", help="Plan only, no Docker modifications")
    parser.add_argument("--challenge", action="append", dest="challenges", help="Limit to specific challenge slug(s)")
    parser.add_argument("--continue-on-error", action="store_true", help="Continue on errors, exit non-zero at end")
    parser.add_argument("--force", action="store_true", help="Allow republishing same tag with different digest")
    parser.add_argument("--output-dir", type=Path, default=Path("dist/publication"), help="Output directory")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Print JSON manifest to stdout")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument(
        "--allow-non-loopback-registry",
        action="store_true",
        help="Allow non-loopback registry bind address (requires explicit confirmation)",
    )
    parser.add_argument(
        "--allow-static-flags",
        action="store_true",
        help="Accept real flags baked into images (disables flag-pattern checks only; "
        "private keys, .env, solve.md checks stay enforced)",
    )

    args = parser.parse_args(argv)

    if not args.root.is_dir():
        parser.error(f"ROOT must be an existing directory: {args.root}")

    version = args.version
    if not version:
        version = read_version_from_file(args.root)
    if not version:
        parser.error("--version is required (or provide a VERSION file in ROOT)")

    try:
        validate_version(version)
        validate_registry(args.registry)
        validate_shell_safe(args.registry, "registry")
        validate_shell_safe(version, "version")
        validate_shell_safe(args.registry_name, "registry-name")
    except ValidationError as e:
        parser.error(str(e))

    if args.bind_address not in ("127.0.0.1", "localhost") and not args.allow_non_loopback_registry:
        parser.error(
            f"Non-loopback bind address {args.bind_address!r} requires --allow-non-loopback-registry"
        )

    if args.dry_run and args.no_create_registry:
        pass  # compatible

    # Sync registry port from --registry if specified
    if ":" in args.registry:
        _, port_str = args.registry.rsplit(":", 1)
        try:
            args.registry_port = int(port_str)
        except ValueError:
            parser.error(f"Invalid port in registry: {args.registry}")

    return PublishConfig(
        root=args.root.resolve(),
        registry=args.registry,
        version=version,
        registry_name=args.registry_name,
        registry_image=args.registry_image,
        registry_volume=args.registry_volume,
        bind_address=args.bind_address,
        registry_port=args.registry_port,
        no_create_registry=args.no_create_registry,
        pull=args.pull,
        no_cache=args.no_cache,
        dry_run=args.dry_run,
        challenges=args.challenges,
        continue_on_error=args.continue_on_error,
        force=args.force,
        output_dir=args.output_dir,
        json_output=args.json_output,
        verbose=args.verbose,
        allow_non_loopback_registry=args.allow_non_loopback_registry,
        allow_static_flags=args.allow_static_flags,
    )


def run_publication(
    config: PublishConfig,
    *,
    docker: DockerCLI | None = None,
) -> tuple[PublicationManifest, int]:
    """Main publication orchestration. Returns (manifest, exit_code)."""
    global _interrupted
    logger = setup_logging(config.verbose)
    if docker is None:
        docker = DockerCLI(LoggingSubprocessRunner(verbose=config.verbose))

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    manifest = PublicationManifest(
        registry=config.registry,
        version=config.version,
        started_at=_utcnow_iso(),
        overall_status=OverallStatus.FAILED,
    )

    exit_code = EXIT_SUCCESS
    had_errors = False
    had_partial = False

    try:
        print_header(config)

        # Discovery
        challenges = discover_challenges(config.root, filter_slugs=config.challenges)
        logger.info("Discovered %d challenge directories", len(challenges))
        print_discovery_table(challenges, config)

        collisions = detect_slug_collisions(challenges)
        if collisions:
            for c in collisions:
                logger.error(c)
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_PREFLIGHT)

        # Preflight validation
        invalid = [c for c in challenges if c.challenge_type == ChallengeType.INVALID]
        if invalid and not config.continue_on_error:
            for c in invalid:
                for err in c.errors:
                    logger.error("[%s] %s", c.slug, err)
            manifest.challenges = [
                ChallengeResult(
                    slug=c.slug, path=c.path.name, type=ChallengeType.INVALID,
                    status=ChallengeStatus.FAILED, errors=c.errors,
                )
                for c in invalid
            ]
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_PREFLIGHT)

        all_preflight_errors: dict[str, list[str]] = {}
        if config.allow_static_flags:
            logger.warning(
                "--allow-static-flags: flags réels acceptés dans les images "
                "(contrôles clés privées / .env / solve.md maintenus)"
            )
        for ch in challenges:
            if ch.challenge_type == ChallengeType.INVALID:
                all_preflight_errors[ch.slug] = ch.errors
                continue
            errors = validate_challenge_preflight(ch, allow_static_flags=config.allow_static_flags)
            if errors:
                all_preflight_errors[ch.slug] = errors

        if all_preflight_errors and not config.continue_on_error:
            for slug, errs in all_preflight_errors.items():
                for err in errs:
                    logger.error("[%s] preflight: %s", slug, err)
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_PREFLIGHT)

        # Compute all target references and detect collisions
        all_refs: list[tuple[str, str, str]] = []
        for ch in challenges:
            if ch.challenge_type == ChallengeType.SINGLE_IMAGE:
                ref = compute_image_reference(config.registry, ch.slug, config.version)
                all_refs.append((ch.slug, "", ref))
            elif ch.challenge_type == ChallengeType.MULTI_SERVICE:
                svcs = resolve_compose_services(ch, config, docker)
                for svc in svcs:
                    if not svc.is_external:
                        all_refs.append((ch.slug, svc.name, svc.registry_reference))

        ref_collisions = detect_reference_collisions(all_refs)
        if ref_collisions:
            for c in ref_collisions:
                logger.error(c)
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_PREFLIGHT)

        if config.dry_run:
            for ch in challenges:
                result = _dry_run_challenge(ch, config, docker)
                manifest.challenges.append(result)
            return _finalize(manifest, config, OverallStatus.DRY_RUN, EXIT_SUCCESS)

        # Docker availability
        try:
            docker.ensure_available()
        except DockerNotFoundError as e:
            logger.error("%s", e)
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_DOCKER)

        if not docker.compose_version():
            logger.error("Docker Compose is not available")
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_DOCKER)

        # Registry
        try:
            ensure_registry(config, docker)
        except RegistryError as e:
            logger.error("Registry error [%s]: %s", e.step, e)
            return _finalize(manifest, config, OverallStatus.FAILED, EXIT_REGISTRY)

        registry_client = RegistryClient(config.registry)

        # Process each challenge
        for ch in challenges:
            if _interrupted:
                had_errors = True
                break

            if ch.slug in all_preflight_errors:
                manifest.challenges.append(ChallengeResult(
                    slug=ch.slug, path=ch.path.name,
                    type=ch.challenge_type, status=ChallengeStatus.FAILED,
                    errors=all_preflight_errors[ch.slug], warnings=ch.warnings,
                ))
                had_errors = True
                if not config.continue_on_error:
                    break
                continue

            if ch.challenge_type == ChallengeType.INVALID:
                manifest.challenges.append(ChallengeResult(
                    slug=ch.slug, path=ch.path.name,
                    type=ChallengeType.INVALID, status=ChallengeStatus.FAILED,
                    errors=ch.errors,
                ))
                had_errors = True
                continue

            try:
                logger.info("=== Challenge: %s (%s) ===", ch.slug, ch.challenge_type.value)
                result = _publish_challenge(ch, config, docker, registry_client, logger)
                manifest.challenges.append(result)
                if result.status == ChallengeStatus.FAILED:
                    had_errors = True
                    if not config.continue_on_error:
                        exit_code = EXIT_BUILD
                        break
            except (BuildError, PushError) as e:
                had_errors = True
                manifest.challenges.append(ChallengeResult(
                    slug=ch.slug, path=ch.path.name,
                    type=ch.challenge_type, status=ChallengeStatus.FAILED,
                    errors=[str(e)], warnings=ch.warnings,
                ))
                exit_code = EXIT_BUILD if isinstance(e, BuildError) else EXIT_PUSH
                if not config.continue_on_error:
                    break
            except VerifyError as e:
                had_errors = True
                manifest.challenges.append(ChallengeResult(
                    slug=ch.slug, path=ch.path.name,
                    type=ch.challenge_type, status=ChallengeStatus.FAILED,
                    errors=[str(e)], warnings=ch.warnings,
                ))
                exit_code = EXIT_VERIFY
                if not config.continue_on_error:
                    break

        if _interrupted:
            return _finalize(manifest, config, OverallStatus.INTERRUPTED, EXIT_BUILD)

        if had_errors and config.continue_on_error:
            return _finalize(manifest, config, OverallStatus.PARTIAL, EXIT_PARTIAL)
        if had_errors:
            return _finalize(manifest, config, OverallStatus.FAILED, exit_code or EXIT_BUILD)

        return _finalize(manifest, config, OverallStatus.SUCCESS, EXIT_SUCCESS)

    except DockerNotFoundError as e:
        logger.error("%s", e)
        return _finalize(manifest, config, OverallStatus.FAILED, EXIT_DOCKER)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        return _finalize(manifest, config, OverallStatus.FAILED, EXIT_BUILD)


def _dry_run_challenge(
    ch: "DiscoveredChallenge",
    config: PublishConfig,
    docker: DockerCLI,
) -> ChallengeResult:
    from .models import DiscoveredChallenge

    if ch.challenge_type == ChallengeType.STATIC:
        return build_challenge_result_static(ch)

    result = ChallengeResult(
        slug=ch.slug,
        path=ch.path.name,
        type=ch.challenge_type,
        status=ChallengeStatus.DRY_RUN,
        warnings=ch.warnings,
    )

    if ch.challenge_type == ChallengeType.SINGLE_IMAGE:
        ref = compute_image_reference(config.registry, ch.slug, config.version)
        from .models import ImagePublication
        result.images.append(ImagePublication(service=None, reference=ref))

    elif ch.challenge_type == ChallengeType.MULTI_SERVICE:
        svcs = resolve_compose_services(ch, config, docker)
        from .models import ImagePublication
        for svc in svcs:
            if svc.is_external:
                result.external_dependencies.append(svc.source_image or svc.registry_reference)
            else:
                result.images.append(ImagePublication(service=svc.name, reference=svc.registry_reference))

    return result


def _publish_challenge(
    ch: "DiscoveredChallenge",
    config: PublishConfig,
    docker: DockerCLI,
    registry_client: RegistryClient,
    logger,
) -> ChallengeResult:
    from .models import DiscoveredChallenge, ImagePublication

    if ch.challenge_type == ChallengeType.STATIC:
        return build_challenge_result_static(ch)

    result = ChallengeResult(
        slug=ch.slug,
        path=ch.path.name,
        type=ch.challenge_type,
        status=ChallengeStatus.PUBLISHED,
        warnings=list(ch.warnings),
    )

    if ch.challenge_type == ChallengeType.SINGLE_IMAGE:
        ref = compute_image_reference(config.registry, ch.slug, config.version)
        existing = verify_remote_publication(
            ref, config, docker, registry_client, challenge=ch.slug
        )
        if existing:
            logger.info("[%s] reusing remote tag: %s", ch.slug, ref)
            result.images.append(existing)
        else:
            logger.info("[%s] building single-image: %s", ch.slug, ref)
            build_single_image(ch, config, docker)
            pub = publish_image(ref, config, docker, registry_client, challenge=ch.slug)
            result.images.append(pub)

    elif ch.challenge_type == ChallengeType.MULTI_SERVICE:
        planned = resolve_compose_services(ch, config, docker)
        built_services = [s for s in planned if s.built]
        remote_hits: dict[str, ImagePublication] = {}
        reuse_all = not config.force and bool(built_services)

        if reuse_all:
            for svc in built_services:
                pub = verify_remote_publication(
                    svc.registry_reference,
                    config,
                    docker,
                    registry_client,
                    challenge=ch.slug,
                    service=svc.name,
                    quiet=True,
                )
                if pub is None:
                    reuse_all = False
                    break
                remote_hits[svc.name] = pub

        if reuse_all:
            logger.info(
                "[%s] images already in registry — skipping build (use --force to rebuild)",
                ch.slug,
            )
            services = planned
            for svc in planned:
                if svc.is_external:
                    result.external_dependencies.append(svc.source_image or "")
            for svc in built_services:
                result.images.append(remote_hits[svc.name])
        else:
            logger.info("[%s] building compose: %s", ch.slug, ch.compose_file.name)
            services = build_compose_images(ch, config, docker)
            for svc in services:
                if svc.is_external:
                    result.external_dependencies.append(svc.source_image or "")
                    continue
                existing = verify_remote_publication(
                    svc.registry_reference,
                    config,
                    docker,
                    registry_client,
                    challenge=ch.slug,
                    service=svc.name,
                    quiet=True,
                )
                if existing:
                    logger.info("[%s/%s] already published: %s", ch.slug, svc.name, svc.registry_reference)
                    result.images.append(existing)
                else:
                    pub = publish_image(
                        svc.registry_reference, config, docker, registry_client,
                        challenge=ch.slug, service=svc.name,
                    )
                    result.images.append(pub)

        compose_config = parse_compose_config(ch.compose_file, ch.path, docker)

        # Generate CTFd compose
        if ch.ctfd_override:
            ctfd_data = apply_ctfd_override(ch.ctfd_override, services, config, ch)
        else:
            ctfd_data = generate_ctfd_compose(ch, services, compose_config, config)

        out_path = write_ctfd_compose(ch, ctfd_data, config)
        result.generated_ctfd_compose = str(out_path.relative_to(config.output_dir))
        logger.info("[%s] generated CTFd compose: %s", ch.slug, result.generated_ctfd_compose)

    # Verify all images published
    if result.images and not all(img.verified for img in result.images):
        result.status = ChallengeStatus.FAILED
        result.errors.append("Not all images verified after push")

    return result


def _finalize(
    manifest: PublicationManifest,
    config: PublishConfig,
    status: OverallStatus,
    exit_code: int,
) -> tuple[PublicationManifest, int]:
    manifest.overall_status = status
    manifest.completed_at = _utcnow_iso()
    write_manifest_atomic(manifest, config)
    print_summary(manifest, exit_code)
    if config.json_output:
        print(json.dumps(manifest.to_dict(), indent=2))
    return manifest, exit_code


def main(argv: list[str] | None = None) -> int:
    try:
        config = parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code != 0 else EXIT_SUCCESS

    _, exit_code = run_publication(config)
    return exit_code
