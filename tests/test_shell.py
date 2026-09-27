"""Shell interactif et modèle d'événement : parcours complet sans Docker, CTFd simulé."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctfcreator.event import Event, list_events
from ctfcreator.shell import CTFCreatorShell

from .fake_ctfd import TOKEN, State, make_server


@pytest.fixture
def ctfd(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CTFD_TOKEN", TOKEN)
    state = State()
    srv = make_server(state)
    yield state, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def shell(tmp_path, monkeypatch, ctfd):
    _, url = ctfd
    monkeypatch.setenv("LABCTL_STATE", str(tmp_path / "labstate"))
    for k in ("FLAG_USER", "FLAG_ROOT"):
        monkeypatch.delenv(k, raising=False)
    ev = Event.create(tmp_path / "ws", "demo-2026", {"name": "Demo", "version": "2026.1", "ctfd_url": url})
    return CTFCreatorShell(tmp_path / "ws", ev)


def set_real_flags(ev: Event) -> None:
    for d in ev.challenges_dir.iterdir():
        for f in [*d.rglob("challenge.yml"), *d.rglob("Dockerfile")]:
            f.write_text(f.read_text().replace("CCTF{local_test_only}", f"CCTF{{real_{d.name.replace('-', '_')}}}"))
    for d in ev.boxes_dir.iterdir():
        f = d / "challenge.yml"
        t = f.read_text()
        t = t.replace('flag: "AFLO{local_test_only}"', 'flag: "AFLO{user_ok_1}"', 1)
        t = t.replace('flag: "AFLO{local_test_only}"', 'flag: "AFLO{root_ok_2}"', 1)
        f.write_text(t)


def test_event_create_and_list(tmp_path):
    ev = Event.create(tmp_path, "Mon CTF 2026", {"name": "Mon CTF"})
    assert ev.slug == "mon-ctf-2026" and (ev.root / "event.yml").is_file()
    assert ev.challenges_dir.is_dir() and ev.boxes_dir.is_dir()
    assert [e.slug for e in list_events(tmp_path)] == ["mon-ctf-2026"]
    ev.set("version", "2027.1")
    assert Event.load(ev.root).get("version") == "2027.1"


def test_templates_to_published(shell, ctfd, capsys):
    state, _ = ctfd
    ev = shell.event
    for c in ("new web login-bypass", "new tcp oracle", "new static logs", "new box pivot"):
        shell.onecmd(c)
    assert (ev.challenges_dir / "oracle" / "src" / "server.py").is_file()
    assert (ev.boxes_dir / "pivot" / "box.yml").is_file()

    rep = shell.do_check("")
    assert not rep.ok                                     # placeholders bloquants
    set_real_flags(ev)
    rep = shell.do_check("")
    assert rep.ok, rep.errors

    # flags de build des box injectés pour labctl (une seule source de vérité)
    shell._bind_labs()
    assert os.environ["FLAG_USER"] == "AFLO{user_ok_1}" and os.environ["FLAG_ROOT"] == "AFLO{root_ok_2}"

    assert shell._publish(None, None, False, True)
    names = {c["name"]: c for c in state.challenges.values()}
    assert {"login-bypass", "oracle", "logs", "pivot · Accès utilisateur", "pivot · Administrateur"} <= set(names)
    assert names["oracle"]["ctype"] == "tcp" and names["oracle"]["image"] == "localhost:5000/oracle:2026.1"
    assert all(c["state"] == "hidden" for c in state.challenges.values())
    out = capsys.readouterr().out
    assert "real_" not in out and "user_ok" not in out     # aucun flag en clair

    shell.onecmd("open oracle -y")
    assert names["oracle"]["state"] == "visible"
    assert names["login-bypass"]["state"] == "hidden"
    shell.onecmd("hide -y")
    assert all(c["state"] == "hidden" for c in state.challenges.values())


def test_derive_resets_flags(shell):
    ev = shell.event
    shell.onecmd("new web base")
    set_real_flags(ev)
    shell.onecmd("derive base base-v2")
    d = ev.challenges_dir / "base-v2"
    assert d.is_dir()
    yml = (d / "challenge.yml").read_text()
    assert "real_base" not in yml and "CCTF{local_test_only}" in yml
    assert "real_base" not in (d / "Dockerfile").read_text()
    assert "dérivé de base" in yml


def test_deploy_pipeline_without_containers(shell, ctfd, capsys):
    state, _ = ctfd
    shell.onecmd("new static logs")
    shell.onecmd("new box pivot")
    set_real_flags(shell.event)
    shell.onecmd("deploy -y")
    out = capsys.readouterr().out
    for word in ("[1/4]", "CONTRÔLE", "[2/4]", "[3/4]", "CTFD", "[4/4]", "BOX", "déployé"):
        assert word in out
    assert len(state.challenges) == 3


def test_deploy_stops_on_check_errors(shell, ctfd, capsys):
    state, _ = ctfd
    shell.onecmd("new web x")               # placeholder -> contrôle KO
    shell.onecmd("deploy -y")
    out = capsys.readouterr().out
    assert "en échec" in out and "[2/4]" not in out
    assert not state.challenges


def test_commands_without_event(tmp_path, capsys):
    sh = CTFCreatorShell(tmp_path, None)
    for c in ("list", "check", "build", "publish", "new web a", "box list", "config"):
        sh.onecmd(c)
    assert "aucun événement chargé" in capsys.readouterr().out
    sh.onecmd("help")
    sh.onecmd("templates")
    sh.onecmd("nimportequoi")
    assert "commande inconnue" in capsys.readouterr().out


def test_load_and_prompt(tmp_path, monkeypatch):
    monkeypatch.delenv("CTFD_TOKEN", raising=False)
    Event.create(tmp_path, "evt", {"name": "Evt", "version": "9.1"})
    sh = CTFCreatorShell(tmp_path, None)
    sh.onecmd("load evt")
    assert sh.event and sh.event.slug == "evt"
    assert "evt" in sh.prompt and "9.1" in sh.prompt


def test_create_wizard(tmp_path, monkeypatch):
    answers = iter(["CTF Corse", "ctf-corse", "Fac CORTE", "", "", "localhost:5000", "2026.2",
                    "http://127.0.0.1", "hidden", ""])
    monkeypatch.setattr("ctfcreator.shell.Prompt.ask", lambda *a, **k: next(answers))
    monkeypatch.setattr("ctfcreator.shell.Confirm.ask", lambda *a, **k: True)
    src = tmp_path / "old"
    (src / "c1").mkdir(parents=True)
    (src / "c1" / "challenge.yml").write_text('name: "C1"\ncategory: X\nflags: ["CCTF{c1_c1_c1}"]\n')
    answers = iter(["CTF Corse", "ctf-corse", "Fac CORTE", "", "", "localhost:5000", "2026.2",
                    "http://127.0.0.1", "hidden", str(src), ""])
    monkeypatch.setattr("ctfcreator.shell.Prompt.ask", lambda *a, **k: next(answers))
    sh = CTFCreatorShell(tmp_path / "ws", None)
    sh.onecmd("create")
    ev = sh.event
    assert ev and ev.slug == "ctf-corse" and ev.get("client") == "Fac CORTE" and ev.get("version") == "2026.2"
    assert (ev.challenges_dir / "c1" / "challenge.yml").is_file()
    assert (src / "c1").is_dir()                            # copie, pas déplacement


def test_cli_accepts_event_dir(tmp_path, ctfd, monkeypatch):
    from ctfcreator.cli import main

    state, url = ctfd
    ev = Event.create(tmp_path, "e", {"name": "E", "version": "1.0", "ctfd_url": url})
    sh = CTFCreatorShell(tmp_path, ev)
    sh.onecmd("new static s1")
    set_real_flags(ev)
    assert main(["validate", str(ev.root)]) == 0
    assert main(["ctfd", str(ev.root), "--apply"]) == 0
    assert [c["name"] for c in state.challenges.values()] == ["s1"]


def test_workspace_env(tmp_path, monkeypatch):
    from ctfcreator.event import default_workspace

    monkeypatch.setenv("CTFCREATOR_EVENTS", str(tmp_path / "x"))
    assert default_workspace() == (tmp_path / "x").resolve()


def test_box_template_is_labctl_compatible(shell):
    import labctl
    from labctl.discovery import discover_boxes

    shell.onecmd("new box pivot")
    labctl.configure(boxes_root=shell.event.boxes_dir)
    boxes = discover_boxes()
    assert [b.name for b in boxes] == ["pivot"] and boxes[0].flags == ["FLAG_USER", "FLAG_ROOT"]
    assert Path(boxes[0].compose_path).is_file()
