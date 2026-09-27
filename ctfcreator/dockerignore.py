"""Ajoute un .dockerignore standard aux challenges mono-conteneur qui n'en ont pas.

Usage :
    ctfcreator dockerignore ./challenges            # plan (aucune écriture)
    ctfcreator dockerignore ./challenges --write    # écrit les fichiers

- Ne touche jamais un .dockerignore existant.
- Refuse d'écrire si le Dockerfile COPY/ADD un fichier que le modèle exclurait
  (le build casserait) : le challenge est listé pour traitement manuel.
"""

from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path

from .publisher.validation import _dockerignore_regex, is_dockerignored

TEMPLATE = """\
# Contexte de build : uniquement ce que l'image doit contenir.
# Fichiers enseignant (flags, solutions, métadonnées CTFd) exclus.
.git
.gitignore
.dockerignore
.venv
__pycache__
*.pyc
.pytest_cache
tests
expected
dist
solve.md
*.md
challenge.yml
challenge.yaml
security-contract.yaml
check_challenge.sh
.env
.env.*
*.pem
*.key
"""

COPY_RE = re.compile(r"^\s*(COPY|ADD)\s+(.+)$", re.IGNORECASE | re.MULTILINE)


def template_rules() -> list[tuple[bool, re.Pattern[str]]]:
    rules = []
    for line in TEMPLATE.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        rules.append((neg, _dockerignore_regex(line.lstrip("!").strip("/"))))
    return rules


def copy_sources(dockerfile: Path) -> list[str]:
    """Sources locales des COPY/ADD (hors --from=, URLs)."""
    sources: list[str] = []
    for m in COPY_RE.finditer(dockerfile.read_text(encoding="utf-8", errors="replace")):
        args = m.group(2).strip()
        if args.startswith("["):
            continue  # forme JSON : rare ici, vérif manuelle
        try:
            tokens = shlex.split(args)
        except ValueError:
            continue
        if any(t.startswith("--from") for t in tokens):
            continue
        tokens = [t for t in tokens if not t.startswith("--")]
        for src in tokens[:-1]:
            if "://" in src:
                continue
            while src.startswith("./"):
                src = src[2:]
            sources.append(src.rstrip("/") or ".")
    return sources


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctfcreator dockerignore")
    ap.add_argument("root", type=Path)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)

    rules = template_rules()
    written, skipped, manual = [], [], []
    for chal in sorted(p for p in args.root.iterdir() if p.is_dir() and not p.name.startswith((".", "_"))):
        dockerfile = chal / "Dockerfile"
        if not dockerfile.is_file():
            continue
        if (chal / ".dockerignore").exists():
            skipped.append(chal.name)
            continue
        broken = [s for s in copy_sources(dockerfile) if s != "." and is_dockerignored(s, rules)]
        if broken:
            manual.append(f"{chal.name}: COPY/ADD de fichiers exclus par le modèle -> {', '.join(broken)}")
            continue
        if args.write:
            (chal / ".dockerignore").write_text(TEMPLATE, encoding="utf-8")
        written.append(chal.name)

    verb = "écrit" if args.write else "à écrire (relancer avec --write)"
    print(f"{len(written)} .dockerignore {verb} : {', '.join(written) or '-'}")
    print(f"{len(skipped)} déjà présents : {', '.join(skipped) or '-'}")
    for line in manual:
        print(f"[MANUEL] {line}")
    return 1 if manual else 0


if __name__ == "__main__":
    raise SystemExit(main())
