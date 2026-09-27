"""Rich console output for the publisher CLI."""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

if TYPE_CHECKING:
    from .models import ChallengeResult, DiscoveredChallenge, PublicationManifest, PublishConfig

__version__ = "1.0.0"


def _console() -> Console:
    no_color = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()
    return Console(no_color=no_color, stderr=True)


def print_header(config: PublishConfig) -> None:
    console = _console()
    console.print(f"\n[bold]CTFd Challenge Image Publisher[/bold] v{__version__}")
    console.print(f"Root: [cyan]{config.root}[/cyan]")
    console.print(f"Registry: [cyan]{config.registry}[/cyan]  Version: [cyan]{config.version}[/cyan]")
    if config.dry_run:
        console.print("[yellow]DRY-RUN mode — no Docker modifications[/yellow]")
    console.print()


def print_discovery_table(challenges: list[DiscoveredChallenge], config: PublishConfig) -> None:
    from .build import resolve_compose_services
    from .docker_cli import DockerCLI
    from .models import ChallengeType
    from .validation import compute_image_reference

    table = Table(title="Discovered Challenges")
    table.add_column("Slug", style="cyan")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Target Images")

    docker = DockerCLI()
    for ch in challenges:
        targets: list[str] = []
        if ch.challenge_type == ChallengeType.SINGLE_IMAGE:
            targets.append(compute_image_reference(config.registry, ch.slug, config.version))
        elif ch.challenge_type == ChallengeType.MULTI_SERVICE:
            for svc in resolve_compose_services(ch, config, docker):
                if not svc.is_external:
                    targets.append(svc.registry_reference)
        elif ch.challenge_type == ChallengeType.STATIC:
            targets.append("(static — no images)")

        status = "invalid" if ch.challenge_type == ChallengeType.INVALID else "ready"
        table.add_row(ch.slug, ch.challenge_type.value, status, "\n".join(targets) or "—")

    _console().print(table)
    _console().print()


def print_summary(manifest: PublicationManifest, exit_code: int) -> None:
    console = _console()
    table = Table(title="Publication Summary")
    table.add_column("Challenge")
    table.add_column("Service")
    table.add_column("Reference")
    table.add_column("Digest")
    table.add_column("Status")

    for ch in manifest.challenges:
        if not ch.images:
            table.add_row(ch.slug, "—", "—", "—", ch.status.value)
            continue
        for img in ch.images:
            digest = (img.digest or "n/a")[:19] + "..." if img.digest and len(img.digest) > 22 else (img.digest or "n/a")
            verified = "[green]verified[/green]" if img.verified else "[red]NOT verified[/red]"
            svc = img.service or "—"
            table.add_row(ch.slug, svc, img.reference, digest, verified)

    console.print(table)

    status = manifest.overall_status.value
    if exit_code == 0:
        md = Markdown(f"## Result: **{status}**\n\nPublication completed successfully.")
    elif exit_code == 10:
        md = Markdown(
            f"## Result: **partial success**\n\n"
            "Some challenges failed. Review errors in the report and re-run with `--continue-on-error` "
            "or fix failing challenges individually via `--challenge`."
        )
    else:
        md = Markdown(
            f"## Result: **{status}** (exit {exit_code})\n\n"
            "Corrective action: review `publication-report.md`, fix reported issues, then re-run."
        )
    console.print(md)
    console.print()
