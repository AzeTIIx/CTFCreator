"""__SLUG__ — squelette. Remplacer par l'application vulnérable (UNE faiblesse déclarée)."""

import os

from flask import Flask

app = Flask(__name__)
FLAG = os.environ.get("CTFD_FLAG") or os.environ.get("FLAG") or "CCTF{local_test_only}"


@app.get("/")
def index():
    return "__SLUG__ : à implémenter"


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
