"""Tests CTFCreator : format challenge.yml, publication CTFd (faux serveur), CLI."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ctfcreator.cli import main
from ctfcreator.spec import discover

from .fake_ctfd import TOKEN, State, make_server

ROOT = Path(__file__).resolve().parents[1]
REAL = "CCTF{real_flag_value_1}"


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def ctfd(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("CTFD_TOKEN", TOKEN)
    state = State()
    srv = make_server(state)
    yield state, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def event(tmp_path) -> Path:
    root = tmp_path / "challenges"
    # conteneur au format standard (Fac CORTE)
    write(root / "jwt-1" / "challenge.yml", f"""
name: "Dashboard Astra"
slug: jwt-1
category: Web / JWT
value: 500
initial: 500
minimum: 100
decay: 20
function: linear
flags:
  - content: "{REAL}"
    type: static
description: |
  Dashboard.
connection_info: "http://{{{{host}}}}:{{{{port}}}}/"
tags: [cwe-345, web]
hints: [{{content: "Regarde le jeton", cost: 10}}]
files: []
ctfd_plugin:
  type: container
  image: "jwt-1:latest"
  port: 1337
  ctype: web
  env: {{FLAG: "{REAL}"}}
  max_memory_mb: 256
  max_cpu: 0.5
""")
    # dossier avec espace (slug publisher normalisé)
    write(root / "Helix Cloud" / "challenge.yml", f"""
name: Helix Cloud
category: Web / Chain
value: 300
flags: ["{REAL}x"]
ctfd_plugin: {{type: container, port: 1337, ctype: web}}
""")
    # statique avec fichier
    write(root / "hash" / "challenge.yml", """
name: "Empreinte"
category: Crypto
value: 100
flags: ["AFLO{demo123}", {type: regex, content: "AFLO\\\\{d.*\\\\}", data: case_insensitive}]
files: [files/empreinte.txt]
""")
    write(root / "hash" / "files" / "empreinte.txt", "abc")
    # dossiers ignorés
    write(root / "_standards" / "challenge.yml", "name: ignoré\n")
    write(root / ".ctfcreator" / "x.txt", "")
    return root


def run(url: str, *args: str) -> int:
    return main([*args, "--url", url, "--registry", "localhost:5000", "--version", "2026.1", "--skip-registry-check"])


# --------------------------------------------------------------------------- spec


def test_spec_normalises_formats(event):
    chs = {c.slug: c for c in discover(event)}
    assert set(chs) == {"jwt-1", "Helix Cloud", "hash"}
    jwt = chs["jwt-1"]
    assert jwt.type == "container" and jwt.container["port"] == 1337 and jwt.function == "linear"
    assert jwt.warnings and "env" in jwt.warnings[0]           # env non supporté par le plugin
    assert chs["hash"].type == "standard" and len(chs["hash"].flags) == 2
    assert all(not c.validate() for c in chs.values())


def test_spec_legacy_and_milestones(tmp_path):
    write(tmp_path / "c00" / "challenge.yml", """
name: C00
category: Découverte
type: container
image: localhost:5000/c00:2026.1
port: 8080
ctype: web
flags: ["AFLO{premiers_pas}"]
""")
    write(tmp_path / "box" / "challenge.yml", """
schema: aster-multi-milestone/1
category: Réseau
scope_notice: Ne tester que votre instance.
milestones:
  - {name: "Jalon 1", value: 50, description: Recon, flag: "AFLO{local_test_only}"}
  - {name: "Jalon 2", value: 50, description: FTP, flag: "AFLO{vrai_flag_ftp}"}
""")
    chs = discover(tmp_path)
    c00 = next(c for c in chs if c.slug == "c00")
    assert c00.type == "container" and c00.image == "localhost:5000/c00:2026.1" and c00.container["port"] == 8080
    j1, j2 = [c for c in chs if c.slug == "box"]
    assert "placeholder" in j1.validate()[0]
    assert not j2.validate() and "Ne tester" in j2.description


def test_spec_errors(tmp_path):
    write(tmp_path / "bad" / "challenge.yml", """
name: Bad
category: X
function: linear
flags: []
files: [absent.txt]
ctfd_plugin: {type: container, ctype: udp}
""")
    errs = discover(tmp_path)[0].validate()
    text = " ".join(errs)
    for needle in ("initial", "aucun flag", "absent.txt", "port", "ctype"):
        assert needle in text


# --------------------------------------------------------------------------- CTFd


def test_plan_is_read_only(ctfd, event, capsys):
    state, url = ctfd
    assert run(url, "ctfd", str(event)) == 0
    assert not state.challenges
    assert all(m == "GET" for m, _ in state.requests)
    out = capsys.readouterr().out
    assert REAL not in out and "real_flag" not in out                 # jamais de flag en clair
    assert "localhost:5000/helix-cloud:2026.1" in out                  # image résolue


def test_apply_creates_everything_then_idempotent(ctfd, event):
    state, url = ctfd
    assert run(url, "ctfd", str(event), "--apply") == 0
    by_name = {c["name"]: c for c in state.challenges.values()}
    jwt = by_name["Dashboard Astra"]
    assert jwt["type"] == "container" and jwt["image"] == "localhost:5000/jwt-1:2026.1"
    assert jwt["port"] == 1337 and jwt["function"] == "linear" and jwt["initial"] == 500
    assert jwt["state"] == "hidden"                                   # défaut prudent
    assert "env" not in jwt
    cid = jwt["id"]
    assert [f["content"] for f in state.of("flags", cid)] == [REAL]
    assert sorted(t["value"] for t in state.of("tags", cid)) == ["cwe-345", "web"]
    assert [(h["content"], h["cost"]) for h in state.of("hints", cid)] == [("Regarde le jeton", 10)]
    hid = by_name["Empreinte"]["id"]
    assert len(state.of("flags", hid)) == 2 and state.of("files", hid)[0]["location"].endswith("empreinte.txt")

    before = json.dumps([state.challenges, state.children], sort_keys=True)
    n = len(state.requests)
    assert run(url, "ctfd", str(event), "--apply") == 0
    assert json.dumps([state.challenges, state.children], sort_keys=True) == before
    assert all(m == "GET" for m, _ in state.requests[n:])            # 2e passage : aucune écriture


def test_update_and_prune(ctfd, event):
    state, url = ctfd
    cid = state.add_challenge(name="Dashboard Astra", type="container", category="Old", image="old:1",
                              port=1337, ctype="web", function="linear", initial=500, minimum=100, decay=20,
                              description="Dashboard.\n", connection_info="http://{{host}}:{{port}}/",
                              max_memory_mb=256, max_cpu=0.5, state="visible")
    state.add_child("flags", cid, type="static", content="CCTF{old_flag_zzz}", data="")
    state.add_child("tags", cid, value="obsolete")
    assert run(url, "ctfd", str(event), "--challenge", "jwt-1", "--apply") == 0
    ch = state.challenges[cid]
    assert ch["category"] == "Web / JWT" and ch["image"] == "localhost:5000/jwt-1:2026.1"
    assert ch["state"] == "visible"                                   # état non touché sans --state
    assert {f["content"] for f in state.of("flags", cid)} == {"CCTF{old_flag_zzz}", REAL}   # pas de prune

    assert run(url, "ctfd", str(event), "--challenge", "jwt-1", "--apply", "--prune", "--state", "hidden") == 0
    assert {f["content"] for f in state.of("flags", cid)} == {REAL}
    assert "obsolete" not in {t["value"] for t in state.of("tags", cid)}
    assert state.challenges[cid]["state"] == "hidden"


def test_link_key_fallback(ctfd, event):
    state, url = ctfd
    state.link_key = "challenge"          # schéma CTFd qui attend `challenge`
    assert run(url, "ctfd", str(event), "--challenge", "hash", "--apply") == 0
    cid = next(c["id"] for c in state.challenges.values() if c["name"] == "Empreinte")
    assert len(state.of("flags", cid)) == 2


def test_blocking_errors(ctfd, event, capsys):
    state, url = ctfd
    state.add_challenge(name="Empreinte", type="container")            # type différent
    write(event / "dup" / "challenge.yml", 'name: "Helix Cloud"\ncategory: X\nflags: ["CCTF{dupdupdup}"]\n')
    assert run(url, "ctfd", str(event), "--apply") == 1
    out = capsys.readouterr().out
    assert "nom en double" in out and "type CTFd" in out
    assert not any(c["name"] == "Helix Cloud" and c.get("category") == "X" for c in state.challenges.values())


def test_manifest_takes_precedence(ctfd, event):
    state, url = ctfd
    pub = event / ".ctfcreator" / "publication"
    pub.mkdir(parents=True)
    (pub / "publication-manifest.json").write_text(json.dumps({"challenges": [
        {"slug": "jwt-1", "images": [{"service": None, "reference": "localhost:5000/jwt-1:9.9", "verified": True}]}
    ]}), encoding="utf-8")
    assert run(url, "ctfd", str(event), "--challenge", "jwt-1", "--apply") == 0
    assert next(iter(state.challenges.values()))["image"] == "localhost:5000/jwt-1:9.9"


def test_bad_token(ctfd, event, monkeypatch):
    _, url = ctfd
    monkeypatch.setenv("CTFD_TOKEN", "nope")
    assert run(url, "ctfd", str(event)) == 3


def test_missing_token(event, monkeypatch):
    monkeypatch.delenv("CTFD_TOKEN", raising=False)
    assert main(["ctfd", str(event)]) == 2


# --------------------------------------------------------------------------- CLI


def test_new_then_validate(tmp_path, capsys):
    root = tmp_path / "challenges"
    root.mkdir()
    assert main(["new", "mon-chall", "--root", str(root)]) == 0
    d = root / "mon-chall"
    assert (d / ".dockerignore").is_file() and "mon-chall" in (d / "src" / "app.py").read_text()
    # placeholder -> invalide tant que le vrai flag n'est pas posé
    assert main(["validate", str(root)]) == 1
    yml = (d / "challenge.yml").read_text().replace("CCTF{local_test_only}", "CCTF{mon_vrai_flag}")
    (d / "challenge.yml").write_text(yml)
    df = (d / "Dockerfile").read_text().replace("CCTF{local_test_only}", "CCTF{mon_vrai_flag}")
    (d / "Dockerfile").write_text(df)
    assert main(["validate", str(root)]) == 1                         # flag cuit refusé par défaut
    assert main(["validate", str(root), "--allow-static-flags"]) == 0
    (root / "ctfcreator.yml").write_text("allow_static_flags: true\n")
    assert main(["validate", str(root)]) == 0                         # réglage lu depuis ctfcreator.yml


def test_templates_are_consistent():
    for name in ("web-container", "static"):
        d = ROOT / "templates" / name
        assert (d / "challenge.yml").is_file() and (d / "solve.md").is_file()
    tmp = ROOT / "templates" / "web-container"
    assert "solve.md" in (tmp / ".dockerignore").read_text()


def test_dockerignore_command(tmp_path):
    d = tmp_path / "c1"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM x\nCOPY src/ /app/\nUSER 1\n")
    assert main(["dockerignore", str(tmp_path)]) == 0 and not (d / ".dockerignore").exists()
    assert main(["dockerignore", str(tmp_path), "--write"]) == 0 and (d / ".dockerignore").exists()


def test_publish_refuses_dry_run(event):
    assert main(["publish", str(event), "--dry-run"]) == 2


@pytest.mark.skipif(not shutil.which("docker"), reason="docker absent")
def test_images_dry_run_uses_hidden_output(event):
    rc = main(["images", str(event), "--version", "2026.1", "--dry-run", "--allow-static-flags"])
    assert rc in (0, 3, 4)


def test_registry_check(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from ctfcreator.ctfd import registry_has_image

    class R(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_HEAD(self):
            self.send_response(200 if self.path == "/v2/jwt-1/manifests/2026.1" else 404)
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), R)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = f"127.0.0.1:{srv.server_port}"
    try:
        assert registry_has_image(f"{host}/jwt-1:2026.1") is True
        assert registry_has_image(f"{host}/jwt-1:2027.1") is False
        assert registry_has_image("ghcr.io/x/y:1") is None
    finally:
        srv.shutdown()
