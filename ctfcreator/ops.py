"""Opérations d'un événement, partagées par la CLI et le shell interactif."""

from __future__ import annotations

import os
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .ctfd import CTFdClient, CTFdError, registry_has_image
from .event import Event
from .publisher.discovery import normalize_slug
from .spec import SpecError
from .sync import Plan, build_plan, load_manifest, resolve_image


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    challenges: int = 0
    boxes: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors


def validate(ev: Event, only: set[str] | None = None) -> Report:
    from .publisher.discovery import discover_challenges
    from .publisher.models import ChallengeType
    from .publisher.validation import validate_challenge_preflight

    rep = Report()
    try:
        specs = ev.ctfd_challenges(only)
    except SpecError as e:
        rep.errors.append(str(e))
        return rep
    rep.challenges = len(specs)
    names: dict[str, str] = {}
    for ch in specs:
        rep.errors.extend(f"{ch.slug} · {e.split(': ', 1)[-1]}" for e in ch.validate())
        rep.warnings.extend(f"{ch.slug} · {w}" for w in ch.warnings)
        if ch.name in names and names[ch.name] != ch.slug:
            rep.errors.append(f"{ch.slug} · nom CTFd {ch.name!r} déjà utilisé par {names[ch.name]}")
        names.setdefault(ch.name, ch.slug)

    if ev.challenges_dir.is_dir():
        allow = bool(ev.get("allow_static_flags"))
        for d in discover_challenges(ev.challenges_dir, filter_slugs=sorted(only) if only else None):
            if d.challenge_type == ChallengeType.STATIC:
                continue
            rep.errors.extend(f"{d.slug} · {e}" for e in validate_challenge_preflight(d, allow_static_flags=allow))

    for box in ev.boxes():
        if only and box.path.name not in only:
            continue
        rep.boxes += 1
        rep.errors.extend(f"box {box.name} · {e}" for e in box.errors)
    return rep


def build_images(ev: Event, *, only: list[str] | None = None, dry_run: bool = False,
                 no_cache: bool = False, force: bool = False) -> int:
    from .publisher.cli import main as publisher_main

    if not ev.challenges_dir.is_dir():
        return 0
    version = str(ev.get("version") or "")
    if not version:
        raise ValueError("`version` absente de event.yml (set version 2026.1)")
    argv = [str(ev.challenges_dir), "--registry", str(ev.get("registry")), "--version", version,
            "--output-dir", str(ev.publication_dir)]
    if ev.get("allow_static_flags"):
        argv.append("--allow-static-flags")
    for slug in only or []:
        argv += ["--challenge", slug]
    if dry_run:
        argv.append("--dry-run")
    if no_cache:
        argv.append("--no-cache")
    if force:
        argv.append("--force")
    return publisher_main(argv)


def client(ev: Event) -> CTFdClient:
    token = os.environ.get("CTFD_TOKEN", "")
    if not token:
        raise CTFdError("CTFD_TOKEN absent (commande `token` dans le shell, ou `read -rs CTFD_TOKEN`)")
    return CTFdClient(str(ev.get("ctfd_url")), token)


def plan(ev: Event, *, only: set[str] | None = None, state: str | None = None,
         prune: bool = False, check_registry: bool = True) -> Plan:
    return build_plan(
        ev.ctfd_challenges(only),
        client(ev),
        manifest=load_manifest(ev.manifest_path),
        registry=str(ev.get("registry")),
        version=str(ev.get("version") or "") or None,
        state=state,
        prune=prune,
        check_registry=check_registry,
    )


# --------------------------------------------------------------------------- statut


@dataclass
class Check:
    label: str
    ok: bool | None
    detail: str = ""


def platform_checks(ev: Event | None) -> list[Check]:
    out = [Check("docker", shutil.which("docker") is not None)]
    registry = str(ev.get("registry")) if ev else "localhost:5000"
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://{registry}/v2/", timeout=3) as r:
            out.append(Check(f"registre {registry}", r.status == 200))
    except (urllib.error.URLError, OSError) as e:
        out.append(Check(f"registre {registry}", False, str(getattr(e, "reason", e))[:60]))
    if ev:
        url = str(ev.get("ctfd_url"))
        if not os.environ.get("CTFD_TOKEN"):
            out.append(Check(f"CTFd {url}", None, "jeton non chargé (commande token)"))
        else:
            try:
                n = len(client(ev).challenges())
                out.append(Check(f"CTFd {url}", True, f"jeton admin valide, {n} challenge(s) en ligne"))
            except CTFdError as e:
                out.append(Check(f"CTFd {url}", False, str(e)[:90]))
    out.append(Check("wireguard (wg)", shutil.which("wg") is not None, "requis pour les box"))
    return out


@dataclass
class ChallengeRow:
    slug: str
    name: str
    type: str
    category: str
    points: str
    flags: int
    image: str
    in_registry: bool | None
    ctfd: str          # absent | hidden | visible | ? | —


def challenge_rows(ev: Event, *, with_ctfd: bool, with_registry: bool) -> list[ChallengeRow]:
    specs = ev.ctfd_challenges()
    manifest = load_manifest(ev.manifest_path)
    remote: dict[str, dict] = {}
    cl = None
    if with_ctfd and os.environ.get("CTFD_TOKEN"):
        try:
            cl = client(ev)
            remote = {c["name"]: c for c in cl.challenges()}
        except CTFdError:
            cl = None
    rows: list[ChallengeRow] = []
    for ch in specs:
        image, present = "", None
        if ch.type == "container":
            image = resolve_image(ch, manifest, str(ev.get("registry")), str(ev.get("version") or "") or None) \
                or f"{normalize_slug(ch.slug)}:?"
            if with_registry:
                present = registry_has_image(image)
        pts = f"{ch.initial}→{ch.minimum}" if ch.function != "static" else str(ch.value)
        state = "—"
        if cl is not None:
            r = remote.get(ch.name)
            if r is None:
                state = "absent"
            else:
                try:
                    state = str(cl.challenge(int(r["id"])).get("state", "?"))
                except CTFdError:
                    state = "?"
        kind = "box" if ch.directory.parent == ev.boxes_dir else ch.type
        rows.append(ChallengeRow(ch.slug, ch.name, kind, ch.category, pts, len(ch.real_flags),
                                 image, present, state))
    return rows

