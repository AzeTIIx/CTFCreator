"""Un CTF = un dossier autonome :

    <workspace>/<slug>/
    ├── event.yml          réglages (nom, dates, registre, version, URL CTFd, WireGuard…)
    ├── challenges/<chall>/   challenges CTFd (conteneur ou statiques)
    ├── boxes/<box>/          box « machine » labctl (box.yml + compose.yml + challenge.yml)
    └── .ctfcreator/          généré : manifeste des images publiées, journaux

L'état labctl (instances, clés WireGuard) est une ressource du VPS : il reste dans
CTFCreator/labs/labctl/state/, commun à tous les événements.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .spec import Challenge, SpecError, discover

EVENT_FILE = "event.yml"
DEFAULTS: dict[str, Any] = {
    "registry": "localhost:5000",
    "version": "",
    "ctfd_url": "http://127.0.0.1",
    "allow_static_flags": True,
    "default_state": "hidden",
}
EDITABLE_KEYS = ("name", "client", "start", "end", "registry", "version", "ctfd_url",
                 "allow_static_flags", "default_state", "wg_endpoint")


class EventError(RuntimeError):
    pass


def default_workspace() -> Path:
    env = os.environ.get("CTFCREATOR_EVENTS")
    if env:
        return Path(env).expanduser().resolve()
    opt = Path("/opt/ctf-events")
    if opt.is_dir():
        return opt
    return (Path.home() / "ctf-events").resolve()


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not s:
        raise EventError(f"nom invalide : {name!r}")
    return s


@dataclass
class BoxInfo:
    name: str
    path: Path
    title: str = ""
    ports: list[int] = field(default_factory=list)
    build_flags: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class Event:
    root: Path
    config: dict[str, Any]

    # ------------------------------------------------------------------ chemins

    @property
    def slug(self) -> str:
        return self.root.name

    @property
    def name(self) -> str:
        return str(self.config.get("name") or self.slug)

    @property
    def challenges_dir(self) -> Path:
        return self.root / "challenges"

    @property
    def boxes_dir(self) -> Path:
        return self.root / "boxes"

    @property
    def work_dir(self) -> Path:
        return self.root / ".ctfcreator"

    @property
    def publication_dir(self) -> Path:
        return self.work_dir / "publication"

    @property
    def manifest_path(self) -> Path:
        return self.publication_dir / "publication-manifest.json"

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, DEFAULTS.get(key, default))

    # ------------------------------------------------------------------ persistance

    @classmethod
    def load(cls, root: Path) -> Event:
        root = root.resolve()
        path = root / EVENT_FILE
        if not path.is_file():
            raise EventError(f"{path} introuvable")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise EventError(f"{path} : document YAML attendu")
        return cls(root, data)

    @classmethod
    def create(cls, workspace: Path, slug: str, config: dict[str, Any]) -> Event:
        root = workspace / slugify(slug)
        if (root / EVENT_FILE).exists():
            raise EventError(f"l'événement existe déjà : {root}")
        for d in (root, root / "challenges", root / "boxes"):
            d.mkdir(parents=True, exist_ok=True)
        ev = cls(root, {**{k: v for k, v in DEFAULTS.items()}, **config})
        ev.save()
        (root / ".gitignore").write_text(".ctfcreator/\n.env\n*.key\n*.pem\n", encoding="utf-8")
        return ev

    def save(self) -> None:
        header = (
            "# event.yml — réglages de l'événement CTFCreator (aucun secret ici ;\n"
            "# jeton CTFd : variable CTFD_TOKEN). Modifiable à la main ou via `set <clé> <valeur>`.\n"
        )
        body = yaml.safe_dump(self.config, allow_unicode=True, sort_keys=False)
        (self.root / EVENT_FILE).write_text(header + body, encoding="utf-8")

    def set(self, key: str, value: str) -> None:
        if key not in EDITABLE_KEYS:
            raise EventError(f"clé non modifiable : {key} ({', '.join(EDITABLE_KEYS)})")
        parsed: Any = value
        if key == "allow_static_flags":
            parsed = value.lower() in ("1", "true", "yes", "oui", "on")
        if key == "default_state" and value not in ("visible", "hidden"):
            raise EventError("default_state : visible | hidden")
        self.config[key] = parsed
        self.save()

    # ------------------------------------------------------------------ contenu

    def challenge_dirs(self) -> list[Path]:
        if not self.challenges_dir.is_dir():
            return []
        return sorted(p for p in self.challenges_dir.iterdir()
                      if p.is_dir() and not p.name.startswith((".", "_")))

    def ctfd_challenges(self, only: set[str] | None = None) -> list[Challenge]:
        """Tout ce qui sera publié dans CTFd : challenges/ + jalons des box (boxes/*/challenge.yml)."""
        out: list[Challenge] = []
        for d in (self.challenges_dir, self.boxes_dir):
            if d.is_dir():
                out.extend(discover(d, only))
        return out

    def boxes(self) -> list[BoxInfo]:
        out: list[BoxInfo] = []
        if not self.boxes_dir.is_dir():
            return out
        for d in sorted(p for p in self.boxes_dir.iterdir() if p.is_dir() and not p.name.startswith((".", "_"))):
            info = BoxInfo(name=d.name, path=d)
            manifest = d / "box.yml"
            if not manifest.is_file():
                info.errors.append("box.yml manquant")
                out.append(info)
                continue
            data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
            info.name = str(data.get("name", d.name))
            info.title = str(data.get("title", ""))
            info.ports = [int(p) for p in data.get("ports", [])]
            info.build_flags = [str(f) for f in data.get("flags", [])]
            compose = d / str(data.get("compose", "compose.yml"))
            if not compose.is_file():
                info.errors.append(f"{compose.name} manquant")
            else:
                cdata = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
                for svc, conf in (cdata.get("services") or {}).items():
                    if isinstance(conf, dict) and conf.get("ports"):
                        info.errors.append(f"service {svc} publie des ports hôte (interdit : accès par VPN)")
                    if isinstance(conf, dict) and conf.get("privileged"):
                        info.errors.append(f"service {svc} privileged")
            missing = [f for f in info.build_flags if f not in self.box_flag_env(d)]
            if missing:
                info.errors.append(
                    f"flag(s) sans valeur réelle dans challenge.yml (build_arg) : {', '.join(missing)}"
                )
            out.append(info)
        return out

    def box_flag_env(self, box_dir: Path) -> dict[str, str]:
        """{FLAG_X: valeur} depuis boxes/<box>/challenge.yml : jalons portant `build_arg`.

        Une seule source de vérité : la même valeur est cuite dans la box (ARG de build)
        et publiée comme flag CTFd du jalon."""
        spec = box_dir / "challenge.yml"
        if not spec.is_file():
            return {}
        try:
            data = yaml.safe_load(spec.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            raise SpecError(f"{spec}: YAML invalide ({e})") from None
        env: dict[str, str] = {}
        from .spec import PLACEHOLDER_FLAGS

        for ms in data.get("milestones") or []:
            arg = ms.get("build_arg")
            flag = ms.get("flag")
            if flag is None and ms.get("flags"):
                first = ms["flags"][0]
                flag = first.get("content") if isinstance(first, dict) else first
            if arg and flag and str(flag).strip().lower() not in PLACEHOLDER_FLAGS:
                env[str(arg)] = str(flag).strip()
        return env

    # ------------------------------------------------------------------ dérivation

    def derive(self, source: Path, new_slug: str, kind: str) -> Path:
        """Copie un challenge / une box existant(e) comme base d'un nouveau."""
        dest_parent = self.boxes_dir if kind == "box" else self.challenges_dir
        dest = dest_parent / slugify(new_slug)
        if dest.exists():
            raise EventError(f"{dest} existe déjà")
        shutil.copytree(source, dest, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".venv", "node_modules", ".pytest_cache", ".ctfcreator", "secrets"))
        old = source.name
        for p in dest.rglob("*"):
            if not p.is_file() or p.suffix not in {".yml", ".yaml", ".md", ".sh", ".txt", ".py", ""}:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            new = _reset_flags(text.replace(old, dest.name))  # jamais réutiliser un flag réel
            if p.name == "challenge.yml":
                new = re.sub(r'(?m)^(name:\s*).*$', rf'\1"{dest.name} (dérivé de {old})"', new, count=1)
            if new != text:
                p.write_text(new, encoding="utf-8")
        return dest


def _reset_flags(text: str) -> str:
    """Remplace les flags réels d'un yml dérivé par un placeholder (évite de réutiliser un flag)."""
    return re.sub(r"\b([A-Z]{2,6})\{[^}\s$]+\}", lambda m: f"{m.group(1)}{{local_test_only}}", text)


def list_events(workspace: Path) -> list[Event]:
    if not workspace.is_dir():
        return []
    out = []
    for d in sorted(workspace.iterdir()):
        if (d / EVENT_FILE).is_file():
            try:
                out.append(Event.load(d))
            except EventError:
                continue
    return out
