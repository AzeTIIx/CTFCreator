"""Format standard `challenge.yml` (CTFCreator v1) : chargement, normalisation, validation.

Un challenge = un dossier contenant `challenge.yml`. Formats acceptés :

- **v1 (standard)** : base ctfcli + bloc `ctfd_plugin` pour les challenges conteneur
  (format Fac CORTE, voir standards/CHALLENGE-SPEC.md) ;
- **legacy AFFLOKAT** : `type: container` + `image` / `port` / `ctype` à la racine ;
- **aster-multi-milestone/1** : un challenge CTFd `standard` par entrée de `milestones`.

Tout est normalisé en `Challenge` ; le reste de l'outil ne connaît que ce modèle.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SPEC_FILENAMES = ("challenge.yml", "challenge.yaml")

PLACEHOLDER_FLAGS = frozenset({
    "aflo{local_test_only}", "cctf{local_test_only}", "esia{local_test_only}",
    "flag{placeholder}", "flag{fake}", "flag{example}", "flag{test}", "flag{changeme}",
    "ctf{placeholder}", "ctf{fake}", "ctf{example}", "ctf{test}",
})
FLAG_TYPES = {"static", "regex"}
STATES = {"visible", "hidden"}
DECAY_FUNCTIONS = {"linear", "logarithmic"}
CTYPES = {"web", "tcp", "ssh"}

# champs du plugin 0xfbad (ContainerChallengeModel) acceptés depuis `ctfd_plugin`
CONTAINER_FIELDS = (
    "port", "ctype", "command", "volumes", "cap_add", "ssh_username",
    "expiration_seconds", "max_renewals", "max_memory_mb", "max_cpu", "docker_context",
)


class SpecError(ValueError):
    """challenge.yml invalide."""


@dataclass(frozen=True)
class Flag:
    content: str
    type: str = "static"
    data: str = ""  # "" = sensible à la casse, "case_insensitive"

    def key(self) -> tuple[str, str, str]:
        return (self.type, self.content, self.data)

    @property
    def is_placeholder(self) -> bool:
        return self.content.strip().lower() in PLACEHOLDER_FLAGS

    @property
    def masked(self) -> str:
        return (self.content[:5] + "***") if len(self.content) > 5 else "***"


@dataclass(frozen=True)
class Hint:
    content: str
    cost: int = 0


@dataclass
class Challenge:
    directory: Path
    source: Path
    name: str
    category: str = ""
    description: str = ""
    connection_info: str = ""
    value: int = 0
    state: str | None = None
    max_attempts: int | None = None
    function: str = "static"
    initial: int | None = None
    minimum: int | None = None
    decay: int | None = None
    flags: list[Flag] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    hints: list[Hint] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    type: str = "standard"            # standard | container
    image: str | None = None          # référence source (yml) ; résolue au moment du sync
    container: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        """Identifiant = nom du dossier (c'est aussi ce qu'utilise le publisher d'images)."""
        return self.directory.name

    @property
    def real_flags(self) -> list[Flag]:
        return [f for f in self.flags if not f.is_placeholder]

    def validate(self) -> list[str]:
        errs: list[str] = []
        where = f"{self.slug}"
        if not self.name.strip():
            errs.append(f"{where}: `name` vide")
        if not self.category.strip():
            errs.append(f"{where}: `category` vide")
        if self.state is not None and self.state not in STATES:
            errs.append(f"{where}: state {self.state!r} invalide (visible|hidden)")
        if self.function not in {"static"} | DECAY_FUNCTIONS:
            errs.append(f"{where}: function {self.function!r} invalide (static|linear|logarithmic)")
        if self.function in DECAY_FUNCTIONS:
            for attr in ("initial", "minimum", "decay"):
                if getattr(self, attr) is None:
                    errs.append(f"{where}: `{attr}` requis avec function={self.function}")
        if not self.flags:
            errs.append(f"{where}: aucun flag")
        elif not self.real_flags:
            errs.append(f"{where}: uniquement des flags placeholder (jamais publiés)")
        for f in self.flags:
            if f.type not in FLAG_TYPES:
                errs.append(f"{where}: type de flag {f.type!r} non géré (static|regex)")
            if f.data not in ("", "case_insensitive"):
                errs.append(f"{where}: data de flag {f.data!r} invalide")
        for p in self.files:
            if not p.is_file():
                errs.append(f"{where}: fichier introuvable {p}")
        if self.type == "container":
            if not self.container.get("port"):
                errs.append(f"{where}: `ctfd_plugin.port` requis pour un challenge conteneur")
            ctype = self.container.get("ctype", "web")
            if ctype not in CTYPES:
                errs.append(f"{where}: ctype {ctype!r} invalide ({'|'.join(sorted(CTYPES))})")
        elif self.type != "standard":
            errs.append(f"{where}: type {self.type!r} non géré (standard|container)")
        return errs


# --------------------------------------------------------------------------- parsing


def _as_int(v: Any, what: str) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        raise SpecError(f"{what}: entier attendu, reçu {v!r}") from None


def _flags(raw: Any, where: str) -> list[Flag]:
    out: list[Flag] = []
    seen: set[tuple[str, str, str]] = set()
    for i, item in enumerate(raw or []):
        if isinstance(item, str):
            f = Flag(item.strip())
        elif isinstance(item, dict) and "content" in item:
            f = Flag(str(item["content"]).strip(), str(item.get("type", "static")), str(item.get("data") or ""))
        else:
            raise SpecError(f"{where}: flags[{i}] illisible")
        if f.key() not in seen:
            seen.add(f.key())
            out.append(f)
    return out


def _hints(raw: Any, where: str) -> list[Hint]:
    out: list[Hint] = []
    for i, item in enumerate(raw or []):
        if isinstance(item, str):
            out.append(Hint(item))
        elif isinstance(item, dict) and "content" in item:
            out.append(Hint(str(item["content"]), _as_int(item.get("cost", 0), f"{where}: hints[{i}].cost") or 0))
        else:
            raise SpecError(f"{where}: hints[{i}] illisible")
    return out


def _tags(raw: Any) -> list[str]:
    out: list[str] = []
    for t in raw or []:
        v = t.get("value") if isinstance(t, dict) else t
        if v is not None and str(v) not in out:
            out.append(str(v))
    return out


def _common(data: dict, directory: Path, source: Path) -> Challenge:
    where = str(source)
    ch = Challenge(
        directory=directory,
        source=source,
        name=str(data.get("name") or "").strip(),
        category=str(data.get("category") or "").strip(),
        description=str(data.get("description") or ""),
        connection_info=str(data.get("connection_info") or ""),
        value=_as_int(data.get("value", 0), f"{where}: value") or 0,
        state=data.get("state"),
        max_attempts=_as_int(data.get("max_attempts"), f"{where}: max_attempts"),
        function=str(data.get("function") or ("linear" if data.get("type") == "dynamic" else "static")),
        initial=_as_int(data.get("initial", (data.get("extra") or {}).get("initial")), f"{where}: initial"),
        minimum=_as_int(data.get("minimum", (data.get("extra") or {}).get("minimum")), f"{where}: minimum"),
        decay=_as_int(data.get("decay", (data.get("extra") or {}).get("decay")), f"{where}: decay"),
        flags=_flags(data.get("flags"), where),
        tags=_tags(data.get("tags")),
        hints=_hints(data.get("hints"), where),
        files=[directory / str(f) for f in (data.get("files") or [])],
    )
    return ch


def _from_standard(data: dict, directory: Path, source: Path) -> Challenge:
    ch = _common(data, directory, source)
    plugin = data.get("ctfd_plugin")
    if isinstance(plugin, dict) and plugin.get("type", "container") == "container":
        ch.type = "container"
        ch.image = plugin.get("image")
        ch.container = {k: plugin[k] for k in CONTAINER_FIELDS if plugin.get(k) not in (None, "")}
        if plugin.get("env"):
            ch.warnings.append(
                "ctfd_plugin.env ignoré : le plugin 0xfbad ne transmet pas de variables par "
                "challenge (flag cuit dans l'image ou volume)"
            )
    elif data.get("type") == "container":  # legacy AFFLOKAT
        ch.type = "container"
        ch.image = data.get("image")
        ch.container = {k: data[k] for k in CONTAINER_FIELDS if data.get(k) not in (None, "")}
    if isinstance(ch.container.get("volumes"), dict):
        ch.container["volumes"] = json.dumps(ch.container["volumes"])
    if ch.type == "container":
        ch.container.setdefault("ctype", "web")
    return ch


def _from_milestones(data: dict, directory: Path, source: Path) -> list[Challenge]:
    out: list[Challenge] = []
    notice = str(data.get("scope_notice") or "").strip()
    for ms in data.get("milestones") or []:
        merged = {
            "category": data.get("category"),
            "state": data.get("state"),
            **ms,
            "flags": ms.get("flags", [ms["flag"]] if "flag" in ms else []),
        }
        if notice:
            merged["description"] = f"{str(ms.get('description') or '').rstrip()}\n\n**Périmètre**\n\n{notice}"
        out.append(_common(merged, directory, source))
    return out


def load_file(path: Path) -> list[Challenge]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise SpecError(f"{path}: YAML invalide ({e})") from None
    if not isinstance(data, dict):
        raise SpecError(f"{path}: document YAML attendu")
    if str(data.get("schema", "")).startswith("aster-multi-milestone"):
        return _from_milestones(data, path.parent, path)
    return [_from_standard(data, path.parent, path)]


def discover(root: Path, only: set[str] | None = None) -> list[Challenge]:
    """Charge tous les `<root>/<slug>/challenge.yml` (les dossiers `_*` et `.*` sont ignorés)."""
    out: list[Challenge] = []
    for d in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))):
        if only and d.name not in only:
            continue
        spec = next((d / n for n in SPEC_FILENAMES if (d / n).is_file()), None)
        if spec is not None:
            out.extend(load_file(spec))
    return out
