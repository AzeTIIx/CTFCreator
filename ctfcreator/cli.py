"""CLI CTFCreator.

    ctfcreator validate ROOT                  contrôle des challenge.yml + préflight sécurité (sans Docker)
    ctfcreator images   ROOT                  build + push des images vers le registre
    ctfcreator ctfd     ROOT [--apply]        plan (par défaut) ou publication dans CTFd
    ctfcreator publish  ROOT                  images puis CTFd (--apply implicite)
    ctfcreator new      SLUG --root ROOT      nouveau challenge depuis un modèle
    ctfcreator [shell [EVENT]]                shell interactif (défaut sans argument)
    ctfcreator dockerignore ROOT [--write]    pose un .dockerignore standard là où il manque

ROOT = dossier d'événement (event.yml + challenges/ + boxes/) ou dossier de challenges simple. Réglages par défaut lus dans
ROOT/ctfcreator.yml (voir templates/ctfcreator.yml). Jeton CTFd : variable CTFD_TOKEN.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

import yaml

from . import __version__
from .ctfd import CTFdClient, CTFdError
from .spec import SpecError, discover
from .sync import apply, build_plan, load_manifest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = PACKAGE_ROOT / "templates"
CONFIG_NAME = "ctfcreator.yml"
PUBLICATION_DIR = Path(".ctfcreator") / "publication"


# --------------------------------------------------------------------------- config


def load_config(root: Path, explicit: Path | None) -> dict:
    path = explicit or (root / CONFIG_NAME)
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: document YAML attendu")
    return data


def pick(cli_value, cfg: dict, key: str, default=None):
    return cli_value if cli_value is not None else cfg.get(key, default)


_EVENT: dict = {}   # rempli par main() quand ROOT est un dossier d'événement


def publication_dir(root: Path) -> Path:
    if _EVENT.get("event"):
        return _EVENT["event"].publication_dir
    return root / PUBLICATION_DIR


def _discover(root: Path, only: set[str] | None):
    if _EVENT.get("event"):
        return _EVENT["event"].ctfd_challenges(only)
    return discover(root, only)


# --------------------------------------------------------------------------- commandes


def cmd_validate(args, cfg: dict) -> int:
    from .publisher.discovery import discover_challenges
    from .publisher.models import ChallengeType
    from .publisher.validation import validate_challenge_preflight

    root = args.root
    allow_static = bool(pick(args.allow_static_flags or None, cfg, "allow_static_flags", False))
    try:
        specs = _discover(root, set(args.challenge) if args.challenge else None)
    except SpecError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        return 2

    errors = 0
    for ch in specs:
        for e in ch.validate():
            print(f"[ERREUR] spec   {e}")
            errors += 1
        for w in ch.warnings:
            print(f"[WARN]   spec   {ch.slug}: {w}")

    for d in discover_challenges(root, filter_slugs=args.challenge):
        if d.challenge_type == ChallengeType.STATIC:
            continue
        for e in validate_challenge_preflight(d, allow_static_flags=allow_static):
            print(f"[ERREUR] sécu   [{d.slug}] {e}")
            errors += 1

    print(f"\n{len(specs)} challenge(s) CTFd lus, {errors} erreur(s)"
          + (" — flags statiques autorisés" if allow_static else ""))
    return 1 if errors else 0


def _images_argv(args, cfg: dict) -> list[str]:
    version = pick(args.version, cfg, "version")
    registry = pick(args.registry, cfg, "registry", "localhost:5000")
    argv = [str(args.root), "--registry", registry, "--output-dir", str(publication_dir(args.root))]
    if version:
        argv += ["--version", str(version)]
    if pick(args.allow_static_flags or None, cfg, "allow_static_flags", False):
        argv.append("--allow-static-flags")
    for slug in args.challenge or []:
        argv += ["--challenge", slug]
    for flag in ("dry_run", "no_cache", "pull", "force", "continue_on_error", "verbose"):
        if getattr(args, flag, False):
            argv.append("--" + flag.replace("_", "-"))
    return argv


def cmd_images(args, cfg: dict) -> int:
    from .publisher.cli import main as publisher_main

    return publisher_main(_images_argv(args, cfg))


def cmd_ctfd(args, cfg: dict, *, force_apply: bool = False) -> int:
    url = pick(args.url, cfg, "ctfd_url", os.environ.get("CTFD_URL", "http://127.0.0.1"))
    token = os.environ.get("CTFD_TOKEN", "")
    if not token:
        print("[ERREUR] CTFD_TOKEN absent : `read -rs CTFD_TOKEN && export CTFD_TOKEN` "
              "(jeton admin : Settings -> Access Tokens)", file=sys.stderr)
        return 2
    manifest_path = args.manifest or publication_dir(args.root) / "publication-manifest.json"
    try:
        specs = _discover(args.root, set(args.challenge) if args.challenge else None)
    except SpecError as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        return 2
    if not specs:
        print("[ERREUR] aucun challenge.yml trouvé", file=sys.stderr)
        return 2

    client = CTFdClient(url, token)
    try:
        plan = build_plan(
            specs,
            client,
            manifest=load_manifest(manifest_path),
            registry=pick(args.registry, cfg, "registry", "localhost:5000"),
            version=str(pick(args.version, cfg, "version", "")) or None,
            state=pick(args.state, cfg, "state"),
            prune=args.prune,
            check_registry=not args.skip_registry_check,
        )
    except CTFdError as e:
        print(f"[ERREUR] API CTFd : {e}", file=sys.stderr)
        return 3

    width = max((len(i.challenge) for i in plan.items), default=10)
    for it in plan.items:
        print(f"{it.challenge:<{width}}  {it.action:<9} {it.detail}")
    counts: dict[str, int] = {}
    for it in plan.items:
        counts[it.action] = counts.get(it.action, 0) + 1
    print("\nPlan : " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    if not (args.apply or force_apply):
        print("Lecture seule. Relancer avec --apply pour publier.")
        return 1 if plan.errors else 0
    if not plan.ops:
        print("Rien à faire.")
        return 1 if plan.errors else 0

    print(f"\nApplication sur {url} ({len(plan.ops)} opérations)…")
    failures = apply(plan)
    print(f"\n{len(plan.ops) - len(failures)} opération(s) OK, {len(failures)} échec(s)"
          + (f", {len(plan.errors)} challenge(s) bloqué(s) au plan" if plan.errors else ""))
    return 1 if failures or plan.errors else 0


def cmd_publish(args, cfg: dict) -> int:
    rc = cmd_images(args, cfg)
    if rc not in (0,):
        print(f"[ERREUR] publication des images en échec (code {rc}) : CTFd non modifié", file=sys.stderr)
        return rc
    return cmd_ctfd(args, cfg, force_apply=True)


def cmd_new(args, cfg: dict) -> int:
    src = TEMPLATES / args.template
    if not src.is_dir():
        print(f"[ERREUR] modèle inconnu : {args.template} ({', '.join(sorted(p.name for p in TEMPLATES.iterdir() if p.is_dir()))})",
              file=sys.stderr)
        return 2
    dest = args.root / args.slug
    if dest.exists():
        print(f"[ERREUR] {dest} existe déjà", file=sys.stderr)
        return 2
    shutil.copytree(src, dest)
    for p in dest.rglob("*"):
        if p.is_file() and p.suffix in {".yml", ".yaml", ".md", ".sh", ".py", ".txt", ""}:
            text = p.read_text(encoding="utf-8")
            if "__SLUG__" in text or "__BOX_NAME__" in text:
                p.write_text(text.replace("__SLUG__", args.slug).replace("__BOX_NAME__", args.slug), encoding="utf-8")
    print(f"Challenge créé : {dest}\nÉtapes : éditer challenge.yml, src/, solve.md, puis `ctfcreator validate {args.root}`.")
    return 0


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ctfcreator", description="Standard de publication de challenges CTFd")
    ap.add_argument("--version-info", action="version", version=f"ctfcreator {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, *, images=False, ctfd=False):
        p.add_argument("root", type=Path, help="Dossier des challenges (un sous-dossier par challenge)")
        p.add_argument("--config", type=Path, help=f"Fichier de réglages (défaut : ROOT/{CONFIG_NAME})")
        p.add_argument("--challenge", action="append", help="Limiter à un dossier de challenge (répétable)")
        p.add_argument("--allow-static-flags", action="store_true",
                       help="Accepter les flags cuits dans les images (sinon lu dans ctfcreator.yml)")
        p.add_argument("--registry", help="Registre (défaut : ctfcreator.yml ou localhost:5000)")
        p.add_argument("--version", help="Tag des images (défaut : ctfcreator.yml)")
        if images:
            for f, h in (("--dry-run", "Plan sans Docker"), ("--no-cache", "Build sans cache"),
                         ("--pull", "Rafraîchir les images de base"), ("--force", "Republier un tag existant"),
                         ("--continue-on-error", "Continuer malgré les erreurs"), ("--verbose", "Logs détaillés")):
                p.add_argument(f, action="store_true", help=h)
        if ctfd:
            p.add_argument("--url", help="URL CTFd (défaut : ctfcreator.yml, $CTFD_URL, http://127.0.0.1)")
            p.add_argument("--manifest", type=Path, help="publication-manifest.json (défaut : ROOT/.ctfcreator/publication/)")
            p.add_argument("--state", choices=["visible", "hidden"], help="Forcer l'état de tous les challenges")
            p.add_argument("--prune", action="store_true", help="Supprimer sur CTFd flags/tags/hints/fichiers absents des yml")
            p.add_argument("--skip-registry-check", action="store_true", help="Ne pas vérifier la présence des images")

    common(sub.add_parser("validate", help="Contrôle des challenge.yml et préflight sécurité"))
    common(sub.add_parser("images", help="Build + push des images"), images=True)
    p = sub.add_parser("ctfd", help="Plan / publication dans CTFd")
    common(p, ctfd=True)
    p.add_argument("--apply", action="store_true", help="Appliquer le plan (sinon lecture seule)")
    common(sub.add_parser("publish", help="Images puis CTFd"), images=True, ctfd=True)

    p = sub.add_parser("new", help="Nouveau challenge depuis un modèle")
    p.add_argument("slug")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--template", default="web-container", help="web-container | static | box")
    sub.add_parser("shell", help="Shell interactif (défaut sans argument) : shell [EVENT]")
    sub.add_parser("dockerignore", help="Pose un .dockerignore standard là où il manque (ROOT [--write])")
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] == "shell":
        from .shell import interactive

        event = Path(argv[1]).expanduser().resolve() if len(argv) > 1 else None
        return interactive(event_path=event)
    if argv[:1] == ["dockerignore"]:
        from .dockerignore import main as dockerignore_main

        return dockerignore_main(argv[1:])
    args = build_parser().parse_args(argv)
    if args.cmd == "new":
        return cmd_new(args, {})
    args.root = args.root.resolve()
    _EVENT.clear()
    if (args.root / "event.yml").is_file():   # ROOT = dossier d'événement
        from .event import Event

        ev = Event.load(args.root)
        _EVENT["event"] = ev
        args.root = ev.challenges_dir
        if not args.root.is_dir():
            args.root.mkdir(parents=True)
    if not args.root.is_dir():
        print(f"[ERREUR] dossier introuvable : {args.root}", file=sys.stderr)
        return 2
    cfg = dict(_EVENT["event"].config) if _EVENT.get("event") else load_config(args.root, args.config)
    if args.cmd == "publish" and getattr(args, "dry_run", False):
        print("[ERREUR] publish --dry-run n'a pas de sens : utiliser `images --dry-run` puis `ctfd` (plan)", file=sys.stderr)
        return 2
    return {
        "validate": cmd_validate,
        "images": cmd_images,
        "ctfd": cmd_ctfd,
        "publish": cmd_publish,
    }[args.cmd](args, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
