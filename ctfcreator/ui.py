"""Rendu console à la GOAD : préfixes [+] [*] [!] [-], mots-clés colorés, phases chronométrées."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import ClassVar

from rich.align import Align
from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.theme import Theme

THEME = Theme({
    "cc.ok": "bold green",
    "cc.ko": "bold red",
    "cc.warn": "bold yellow",
    "cc.url": "underline cyan",
    "cc.image": "magenta",
    "cc.path": "blue",
    "cc.flag": "bold yellow",
    "cc.duration": "dim cyan",
    "cc.keyword": "bold cyan",
    "cc.state_visible": "bold green",
    "cc.state_hidden": "yellow",
    "cc.number": "bold white",
    "cc.type": "bright_magenta",
})


class CTFHighlighter(RegexHighlighter):
    """Colore automatiquement les éléments reconnaissables dans les messages."""

    base_style = "cc."
    highlights: ClassVar[list[str]] = [
        r"(?P<ok>\b(?:OK|PASS|up|prêt|créé|publié|à jour|succès)\b)",
        r"(?P<ko>\b(?:KO|FAIL|ÉCHEC|down|erreur|absent|refusé|bloqué)\b)",
        r"(?P<warn>\b(?:WARN|attention|non vérifiable|placeholder)\b)",
        r"(?P<url>https?://[^\s\]\)]+)",
        r"(?P<image>\b[\w.-]+(?::\d+)?/[\w./-]+:[\w.-]+\b)",
        r"(?P<flag>\b[A-Z]{2,6}\{\*\*\*)",
        r"(?P<duration>\b\d+(?:[.,]\d+)?\s?s\b)",
        r"(?P<state_visible>\bvisible\b)",
        r"(?P<state_hidden>\bhidden\b)",
        r"(?P<type>\b(?:container|standard|box|static)\b)",
        r"(?P<keyword>\b(?:CTFd|registre|WireGuard|labctl|préflight|build|push|publish|deploy)\b)",
    ]


console = Console(theme=THEME, highlighter=CTFHighlighter())

BANNER = r"""
  ____ _____ _____ ____                _
 / ___|_   _|  ___/ ___|_ __ ___  __ _| |_ ___  _ __
| |     | | | |_ | |   | '__/ _ \/ _` | __/ _ \| '__|
| |___  | | |  _|| |___| | |  __/ (_| | || (_) | |
 \____| |_| |_|   \____|_|  \___|\__,_|\__\___/|_|
"""


def banner(version: str) -> Panel:
    body = Text(BANNER, style="bold cyan")
    body.append("\n  challenges conteneur · box WireGuard · publication CTFd\n", style="dim")
    return Panel(Align.center(body), border_style="cyan",
                 subtitle=f"[dim]ctfcreator {version} — tape [bold]help[/bold][/dim]")


# --------------------------------------------------------------------------- journal


def info(msg: str) -> None:
    console.print(Text("[*] ", style="bold blue") + console.render_str(msg))


def success(msg: str) -> None:
    console.print(Text("[+] ", style="bold green") + console.render_str(msg))


def warn(msg: str) -> None:
    console.print(Text("[!] ", style="bold yellow") + console.render_str(msg))


def error(msg: str) -> None:
    console.print(Text("[-] ", style="bold red") + console.render_str(msg))


def step(ok: bool | None, label: str, detail: str = "") -> None:
    """Ligne de résultat d'une étape : OK / KO / · (ignoré)."""
    tag = Text("  OK  ", style="bold black on green") if ok else (
        Text("  KO  ", style="bold white on red") if ok is False else Text("  ··  ", style="black on yellow"))
    line = tag + Text(" ") + console.render_str(label)
    if detail:
        line += Text(" ") + Text(detail, style="dim")
    console.print(line)


# --------------------------------------------------------------------------- phases


class PhaseResult:
    def __init__(self) -> None:
        self.ok = True
        self.notes: list[str] = []

    def fail(self, note: str = "") -> None:
        self.ok = False
        if note:
            self.notes.append(note)


@contextmanager
def phase(index: int, total: int, title: str, subtitle: str = ""):
    """En-tête de phase numérotée + durée et verdict en sortie (style provisioning GOAD)."""
    console.print()
    console.print(Rule(
        f"[bold cyan][{index}/{total}][/bold cyan] [bold white]{title.upper()}[/bold white]"
        + (f"  [dim]{subtitle}[/dim]" if subtitle else ""),
        style="cyan", align="left",
    ))
    res = PhaseResult()
    t0 = time.monotonic()
    try:
        yield res
    except KeyboardInterrupt:
        res.fail("interrompu")
        raise
    finally:
        dt = time.monotonic() - t0
        if res.ok:
            success(f"{title} terminé en {dt:.1f}s")
        else:
            error(f"{title} en échec après {dt:.1f}s" + (f" — {'; '.join(res.notes)}" if res.notes else ""))
