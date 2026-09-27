"""Publication des challenges dans CTFd : plan (lecture seule) puis application.

Identité d'un challenge = son `name` exact. Pour chaque challenge.yml :
- absent de CTFd  -> création (type standard ou container) + flags, tags, hints, fichiers ;
- présent         -> mise à jour des champs qui diffèrent + ajout de ce qui manque ;
- `prune=True`    -> suppression sur CTFd des flags / tags / hints / fichiers absents du yml.

Les flags ne sont jamais affichés en clair. Les placeholders ne sont jamais publiés.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ctfd import CTFdClient, CTFdError, registry_has_image
from .publisher.discovery import normalize_slug
from .spec import DECAY_FUNCTIONS, Challenge

# --------------------------------------------------------------------------- images


def load_manifest(path: Path | None) -> dict[str, str]:
    """publication-manifest.json du publisher -> {dossier: référence registre}."""
    if not path or not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for ch in doc.get("challenges", []):
        images = [i for i in ch.get("images", []) if i.get("reference")]
        if not images:
            continue
        entry = next((i for i in images if not i.get("service")), images[0])
        out[str(ch.get("slug"))] = entry["reference"]
    return out


def resolve_image(ch: Challenge, manifest: dict[str, str], registry: str | None, version: str | None) -> str | None:
    """Ordre : manifeste du publisher > référence registre explicite du yml > registry/slug:version."""
    if ch.slug in manifest:
        return manifest[ch.slug]
    img = (ch.image or "").strip()
    if img and "/" in img and not img.endswith(":latest"):
        return img
    if registry and version:
        return f"{registry}/{normalize_slug(ch.slug)}:{version}"
    return None


# --------------------------------------------------------------------------- plan


@dataclass
class Item:
    challenge: str
    action: str          # create | update | ok | add-flag | add-tag | ... | error | warn
    detail: str = ""


@dataclass
class Plan:
    items: list[Item] = field(default_factory=list)
    ops: list[tuple[str, str, Callable[[], None]]] = field(default_factory=list)

    def add(self, challenge: str, action: str, detail: str = "", op: Callable[[], None] | None = None) -> None:
        self.items.append(Item(challenge, action, detail))
        if op is not None:
            self.ops.append((challenge, action, op))

    @property
    def errors(self) -> list[Item]:
        return [i for i in self.items if i.action == "error"]


def _desired_payload(ch: Challenge, image: str | None, state: str | None, creating: bool) -> dict[str, Any]:
    p: dict[str, Any] = {
        "name": ch.name,
        "category": ch.category,
        "description": ch.description,
        "connection_info": ch.connection_info,
        "function": ch.function,
    }
    if ch.function in DECAY_FUNCTIONS:
        p.update(initial=ch.initial, minimum=ch.minimum, decay=ch.decay)
        if creating:
            p["value"] = ch.initial
    else:
        p["value"] = ch.value
    if ch.max_attempts is not None:
        p["max_attempts"] = ch.max_attempts
    if state is not None:
        p["state"] = state
    if ch.type == "container":
        p["image"] = image
        p.update(ch.container)
    if creating:
        p["type"] = ch.type
        p.setdefault("state", "hidden")
    return p


def _norm(v: Any) -> Any:
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, str):
        s = v.replace("\r\n", "\n").strip()
        try:
            f = float(s)
            return int(f) if f.is_integer() else f
        except ValueError:
            return s
    return v


def _changed_fields(desired: dict[str, Any], remote: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in desired.items() if k not in remote or _norm(remote.get(k)) != _norm(v)}


def build_plan(
    challenges: list[Challenge],
    client: CTFdClient,
    *,
    manifest: dict[str, str],
    registry: str | None,
    version: str | None,
    state: str | None = None,
    prune: bool = False,
    check_registry: bool = True,
) -> Plan:
    plan = Plan()
    remote_by_name: dict[str, list[dict]] = {}
    for rc in client.challenges():
        remote_by_name.setdefault(rc["name"], []).append(rc)

    names: dict[str, str] = {}
    for ch in challenges:
        label = ch.name or ch.slug
        if ch.name in names:
            plan.add(label, "error", f"nom en double dans les yml ({names[ch.name]} et {ch.slug})")
            continue
        names[ch.name] = ch.slug

        errs = ch.validate()
        for w in ch.warnings:
            if not w.startswith("ctfd_plugin.env"):  # signalé par `validate`, sans effet sur CTFd
                plan.add(label, "warn", w)
        if errs:
            for e in errs:
                plan.add(label, "error", e.split(": ", 1)[-1])
            continue

        image = None
        if ch.type == "container":
            image = resolve_image(ch, manifest, registry, version)
            if not image:
                plan.add(label, "error", "image non résolue : fournir --manifest ou --registry + --version")
                continue
            if check_registry:
                present = registry_has_image(image)
                if present is False:
                    plan.add(label, "error", f"image absente du registre : {image} (publier les images d'abord)")
                    continue
                if present is None:
                    plan.add(label, "warn", f"présence de {image} non vérifiable depuis cette machine")

        eff_state = state if state is not None else ch.state
        matches = remote_by_name.get(ch.name, [])
        if len(matches) > 1:
            plan.add(label, "error", f"{len(matches)} challenges CTFd portent ce nom : {[m['id'] for m in matches]}")
            continue

        if not matches:
            payload = _desired_payload(ch, image, eff_state, creating=True)
            box: dict[str, int] = {}

            def create(ch=ch, payload=payload, box=box) -> None:
                box["id"] = int(client.create_challenge(payload)["id"])

            detail = f"{ch.type}" + (f" · {image}" if image else "") + f" · state={payload['state']}"
            plan.add(label, "create", detail, create)
            _plan_children(plan, client, ch, label, lambda box=box: box["id"], existing=None, prune=False)
            continue

        remote = matches[0]
        cid = int(remote["id"])
        if remote.get("type") != ch.type:
            plan.add(label, "error", f"type CTFd {remote.get('type')!r} ≠ yml {ch.type!r} (changer de type = recréer à la main)")
            continue
        detail_remote = client.challenge(cid)
        changes = _changed_fields(_desired_payload(ch, image, eff_state, creating=False), detail_remote)
        if changes:
            plan.add(label, "update", f"#{cid} champs : {', '.join(sorted(changes))}",
                     lambda cid=cid, changes=changes: client.update_challenge(cid, changes))
        else:
            plan.add(label, "ok", f"#{cid} champs à jour")
        existing = {kind: client.sub(cid, kind) for kind in ("flags", "tags", "hints", "files")}
        _plan_children(plan, client, ch, label, lambda cid=cid: cid, existing=existing, prune=prune)
    return plan


def _plan_children(
    plan: Plan,
    client: CTFdClient,
    ch: Challenge,
    label: str,
    cid: Callable[[], int],
    *,
    existing: dict[str, list[dict]] | None,
    prune: bool,
) -> None:
    ex = existing or {"flags": [], "tags": [], "hints": [], "files": []}

    # flags
    remote_flags = {
        (f.get("type", "static"), (f.get("content") or "").strip(), f.get("data") or ""): f for f in ex["flags"]
    }
    wanted = {f.key() for f in ch.real_flags}
    for f in ch.real_flags:
        if f.key() not in remote_flags:
            plan.add(label, "add-flag", f"{f.type} {f.masked}",
                     lambda f=f: client.create_flag(cid(), f.content, f.type, f.data))
    for key, rf in remote_flags.items():
        if key not in wanted:
            if prune:
                plan.add(label, "del-flag", f"{key[0]} {key[1][:5]}***", lambda rf=rf: client.delete("flags", rf["id"]))
            else:
                plan.add(label, "keep", f"flag {key[1][:5]}*** présent sur CTFd, absent du yml")

    # tags
    remote_tags = {t.get("value"): t for t in ex["tags"]}
    for t in ch.tags:
        if t not in remote_tags:
            plan.add(label, "add-tag", t, lambda t=t: client.create_tag(cid(), t))
    if prune:
        for v, rt in remote_tags.items():
            if v not in ch.tags:
                plan.add(label, "del-tag", str(v), lambda rt=rt: client.delete("tags", rt["id"]))

    # hints
    remote_hints = {(h.get("content") or "").strip(): h for h in ex["hints"]}
    for h in ch.hints:
        if h.content.strip() not in remote_hints:
            plan.add(label, "add-hint", f"coût {h.cost}", lambda h=h: client.create_hint(cid(), h.content, h.cost))
    if prune:
        wanted_h = {h.content.strip() for h in ch.hints}
        for content, rh in remote_hints.items():
            if content not in wanted_h:
                plan.add(label, "del-hint", content[:30], lambda rh=rh: client.delete("hints", rh["id"]))

    # fichiers (comparés par nom de fichier)
    remote_files = {str(f.get("location", "")).rsplit("/", 1)[-1]: f for f in ex["files"]}
    for p in ch.files:
        if p.name not in remote_files:
            plan.add(label, "add-file", p.name, lambda p=p: client.upload_file(cid(), p))
    if prune:
        wanted_f = {p.name for p in ch.files}
        for fname, rf in remote_files.items():
            if fname not in wanted_f:
                plan.add(label, "del-file", fname, lambda rf=rf: client.delete("files", rf["id"]))


def apply(plan: Plan, log: Callable[[str], None] = print) -> list[str]:
    """Exécute les opérations dans l'ordre du plan.

    Si la création ou la mise à jour d'un challenge échoue, ses flags/tags/hints/fichiers
    sont sautés ; les autres challenges continuent."""
    failures: list[str] = []
    broken: set[str] = set()
    for label, action, op in plan.ops:
        if label in broken:
            continue
        try:
            op()
            log(f"  [OK] {label} : {action}")
        except CTFdError as e:
            failures.append(f"{label} : {action} : {e}")
            log(f"  [ÉCHEC] {label} : {action} : {e}")
            if action in ("create", "update"):
                broken.add(label)
    return failures
