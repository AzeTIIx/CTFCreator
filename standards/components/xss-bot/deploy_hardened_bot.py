#!/usr/bin/env python3
"""Deploy hardened XSS bot to all XSS challenges + exam-final."""
from __future__ import annotations

from pathlib import Path

import os  # noqa: E402

# Dossier des challenges : CHALLENGES_ROOT=<client>/challenges (un sous-dossier par challenge)
ROOT = Path(os.environ.get("CHALLENGES_ROOT", ".")).resolve()
SRC = Path(__file__).resolve().parent / "bot_xss_hardened.py"
TARGETS = [
    "xss-blind",
    "xss-csp-1",
    "xss-csp-2",
    "xss-dom",
    "xss-reflected",
    "xss-stored",
    "exam-final",
]


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    # Keep ASCII-safe docstring punctuation for Windows toolchains
    for old, new in (
        ("\u2014", "-"),
        ("\u2013", "-"),
        ("\u2019", "'"),
        ("\u2018", "'"),
        ("\u2026", "..."),
    ):
        text = text.replace(old, new)
    SRC.write_text(text, encoding="utf-8")

    for name in TARGETS:
        dest = ROOT / name / "src" / "bot.py"
        dest.write_text(text, encoding="utf-8")
        print(f"bot -> {name}")

        app = ROOT / name / "src" / "app.py"
        if app.exists():
            c = app.read_text(encoding="utf-8")
            n = c.replace("timeout=30", "timeout=60")
            if n != c:
                app.write_text(n, encoding="utf-8")
                print(f"  timeout -> 60: {name}")


if __name__ == "__main__":
    main()
