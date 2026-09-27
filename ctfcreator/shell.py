"""Shell interactif CTFCreator (REPL à la GOAD).

    ctfcreator            # ou : ctfcreator shell

Un CTF = un dossier d'événement (event.yml + challenges/ + boxes/). Le shell enchaîne
création, dérivation depuis les modèles, contrôle, build, publication CTFd et box labctl.
"""

from __future__ import annotations

import cmd
import getpass
import os
import shlex
import shutil
from datetime import datetime
from pathlib import Path

from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from . import __version__, ops
from .ctfd import CTFdError
from .event import Event, EventError, default_workspace, list_events, slugify
from .spec import SpecError
from .sync import apply as apply_plan
from .ui import banner, console, error, info, phase, step, success, warn

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = PACKAGE_ROOT / "templates"
LABS_STATE = PACKAGE_ROOT / "labs" / "labctl" / "state"

# modèle -> (dossier du modèle, catégorie d'objet)
TEMPLATES = {
    "web": ("web-container", "challenge", "Application web conteneurisée (Flask, port 1337, ctype web)"),
    "tcp": ("tcp-container", "challenge", "Service TCP brut (nc, port 1337, ctype tcp) : crypto, pwn, misc"),
    "static": ("static", "challenge", "Challenge sans conteneur : fichiers à analyser hors ligne"),
    "box": ("box", "box", "Machine par binôme via WireGuard (labctl) : foothold → privesc → pivot"),
}

HELP_GROUPS = [
    ("Événement", ["events", "create", "load", "config", "set", "status"]),
    ("Contenu", ["templates", "new", "derive", "list", "check"]),
    ("Déploiement", ["build", "publish", "deploy", "open", "hide"]),
    ("Box / labctl", ["box", "labs"]),
    ("Session", ["token", "clear", "exit"]),
]


class CTFCreatorShell(cmd.Cmd):
    intro = ""
    doc_header = ""

    def __init__(self, workspace: Path | None = None, event: Event | None = None):
        super().__init__()
        self.workspace = workspace or default_workspace()
        self.event: Event | None = event
        self._refresh_prompt()
        if event:
            self._bind_labs()

    # ------------------------------------------------------------------ outillage

    def _refresh_prompt(self) -> None:
        ev = self.event.slug if self.event else "-"
        ver = (self.event.get("version") or "?") if self.event else "-"
        tok = "\001\033[1;32m\002●" if os.environ.get("CTFD_TOKEN") else "\001\033[1;31m\002○"
        self.prompt = (f"\001\033[1;36m\002CTFCreator\001\033[0m\002/\001\033[1;33m\002{ev}"
                       f"\001\033[0m\002/\001\033[35m\002{ver}\001\033[0m\002 {tok}\001\033[0m\002 > ")

    def _need_event(self) -> Event | None:
        if not self.event:
            warn("aucun événement chargé : [bold]load <slug>[/bold] ou [bold]create[/bold]")
        return self.event

    def _bind_labs(self) -> None:
        """Pointe labctl sur boxes/ de l'événement + injecte les flags de build des box."""
        try:
            import labctl

            labctl.configure(boxes_root=self.event.boxes_dir, state_dir=os.environ.get("LABCTL_STATE") or LABS_STATE)
        except ImportError:
            return
        for box in self.event.boxes():
            try:
                os.environ.update(self.event.box_flag_env(box.path))
            except SpecError:
                continue

    def _args(self, arg: str) -> list[str]:
        try:
            return shlex.split(arg)
        except ValueError as e:
            error(f"arguments illisibles : {e}")
            return []

    # ------------------------------------------------------------------ aide

    def do_help(self, arg):
        "help [commande] : aide générale ou détaillée."
        if arg:
            return super().do_help(arg)
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="bold cyan", no_wrap=True)
        t.add_column(style="bold")
        t.add_column(style="dim")
        for group, cmds in HELP_GROUPS:
            t.add_row(f"[bold white]{group}[/bold white]", "", "")
            for c in cmds:
                doc = (getattr(self, f"do_{c}").__doc__ or "").split(" : ", 1)
                t.add_row("", escape(doc[0] if len(doc) == 2 else c), escape(doc[-1]))
        console.print(Panel(t, title="Commandes", border_style="cyan"))

    # ------------------------------------------------------------------ événement

    def do_events(self, _arg):
        "events : liste les événements du workspace."
        evs = list_events(self.workspace)
        t = Table(title=f"Événements — {self.workspace}", title_style="bold")
        for col in ("Slug", "Nom", "Client", "Version", "Challenges", "Box"):
            t.add_column(col, style="cyan" if col == "Slug" else None)
        for ev in evs:
            t.add_row(ev.slug, ev.name, str(ev.get("client", "")), str(ev.get("version", "")),
                      str(len(ev.challenge_dirs())), str(len(ev.boxes())))
        if not evs:
            t.add_row("[dim]aucun — tape create[/dim]", "", "", "", "", "")
        console.print(t)

    def do_create(self, arg):
        "create [slug] : assistant de création d'un CTF (réglages + import de challenges existants)."
        console.print(Panel("[bold]Nouvel événement[/bold] — Entrée = valeur par défaut", border_style="cyan"))
        name = Prompt.ask("Nom affiché", default=arg or "CTF")
        slug = Prompt.ask("Identifiant (dossier)", default=slugify(arg or name))
        cfg = {
            "name": name,
            "client": Prompt.ask("Client", default=""),
            "start": Prompt.ask("Début (AAAA-MM-JJ HH:MM, optionnel)", default=""),
            "end": Prompt.ask("Fin (optionnel)", default=""),
            "registry": Prompt.ask("Registre d'images", default="localhost:5000"),
            "version": Prompt.ask("Version (tag immuable des images)", default=f"{datetime.now().astimezone().year}.1"),
            "ctfd_url": Prompt.ask("URL CTFd vue du VPS", default="http://127.0.0.1"),
            "allow_static_flags": Confirm.ask("Flags statiques cuits dans les images ?", default=True),
            "default_state": Prompt.ask("État à la création", choices=["hidden", "visible"], default="hidden"),
        }
        cfg = {k: v for k, v in cfg.items() if v != ""}
        try:
            ev = Event.create(self.workspace, slug, cfg)
        except EventError as e:
            error(str(e))
            return
        success(f"événement créé : [cc.path]{ev.root}[/cc.path]")
        src = Prompt.ask("Importer des challenges existants (dossier, vide = non)", default="")
        if src:
            self._import(ev, Path(src).expanduser(), "challenge")
        src = Prompt.ask("Importer des box labctl existantes (dossier, vide = non)", default="")
        if src:
            self._import(ev, Path(src).expanduser(), "box")
        self.event = ev
        self._bind_labs()
        self._refresh_prompt()
        self.do_list("")

    def _import(self, ev: Event, src: Path, kind: str) -> None:
        if not src.is_dir():
            error(f"dossier introuvable : {src}")
            return
        dest_parent = ev.boxes_dir if kind == "box" else ev.challenges_dir
        marker = "box.yml" if kind == "box" else "challenge.yml"
        n = 0
        for d in sorted(p for p in src.iterdir() if p.is_dir() and not p.name.startswith((".", "_"))):
            if not (d / marker).is_file() and not (kind == "challenge" and (d / "Dockerfile").is_file()):
                continue
            dest = dest_parent / d.name
            if dest.exists():
                warn(f"{d.name} existe déjà, ignoré")
                continue
            shutil.copytree(d, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", ".ctfcreator"))
            n += 1
        success(f"{n} {kind}(s) importé(s) depuis [cc.path]{src}[/cc.path] (copie, l'original est intact)")

    def do_load(self, arg):
        "load <slug|chemin> : charge un événement."
        target = arg.strip()
        if not target:
            self.do_events("")
            return
        path = Path(target).expanduser()
        root = path if (path / "event.yml").is_file() else self.workspace / target
        try:
            self.event = Event.load(root)
        except EventError as e:
            error(str(e))
            return
        self._bind_labs()
        self._refresh_prompt()
        success(f"événement chargé : [bold]{self.event.name}[/bold] ([cc.path]{self.event.root}[/cc.path])")

    def complete_load(self, text, *_):
        return [e.slug for e in list_events(self.workspace) if e.slug.startswith(text)]

    do_use = do_load
    complete_use = complete_load

    def do_config(self, _arg):
        "config : affiche les réglages de l'événement."
        ev = self._need_event()
        if not ev:
            return
        t = Table(show_header=False, box=None)
        t.add_column(style="bold cyan")
        t.add_column()
        for k in ("name", "client", "start", "end", "registry", "version", "ctfd_url",
                  "allow_static_flags", "default_state", "wg_endpoint"):
            t.add_row(k, str(ev.get(k, "") if ev.get(k) is not None else ""))
        t.add_row("dossier", str(ev.root))
        console.print(Panel(t, title=f"event.yml — {ev.slug}", border_style="cyan"))

    def do_set(self, arg):
        "set <clé> <valeur> : modifie event.yml (version, ctfd_url, wg_endpoint, default_state…)."
        ev = self._need_event()
        args = self._args(arg)
        if not ev or len(args) < 2:
            if ev:
                warn("usage : set <clé> <valeur>")
            return
        try:
            ev.set(args[0], " ".join(args[1:]))
        except EventError as e:
            error(str(e))
            return
        if args[0] == "wg_endpoint":
            self._labctl(f"endpoint {args[1]}", quiet=True)
        self._refresh_prompt()
        success(f"{args[0]} = {' '.join(args[1:])}")

    def complete_set(self, text, *_):
        from .event import EDITABLE_KEYS

        return [k for k in EDITABLE_KEYS if k.startswith(text)]

    def do_status(self, arg):
        "status [--no-ctfd] : tableau de bord (plateforme, challenges, registre, CTFd, box)."
        ev = self._need_event()
        if ev:
            when = " → ".join(str(x) for x in (ev.get("start"), ev.get("end")) if x) or "dates non définies"
            console.print(Panel(
                f"[bold]{escape(ev.name)}[/bold]  [dim]{escape(str(ev.get('client') or ''))}[/dim]\n"
                f"{when} · version [cc.image]{escape(str(ev.get('version')))}[/] · registre {escape(str(ev.get('registry')))}"
                f" · CTFd {escape(str(ev.get('ctfd_url')))}\n"
                f"[cc.path]{escape(str(ev.root))}[/cc.path]",
                title="Événement", border_style="cyan"))
        t = Table(title="Plateforme", title_style="bold", show_header=False)
        t.add_column(no_wrap=True)
        t.add_column()
        t.add_column(style="dim")
        for c in ops.platform_checks(ev):
            mark = "[cc.ok]OK[/]" if c.ok else ("[cc.ko]KO[/]" if c.ok is False else "[cc.warn]··[/]")
            t.add_row(mark, c.label, c.detail)
        console.print(t)
        if not ev:
            return
        self.do_list("" if "--no-ctfd" in arg else "--ctfd")
        self._labctl("list", quiet=True)

    # ------------------------------------------------------------------ contenu

    def do_templates(self, _arg):
        "templates : liste les modèles de challenge et de box."
        t = Table(title="Modèles", title_style="bold")
        t.add_column("Nom", style="bold cyan")
        t.add_column("Type")
        t.add_column("Usage")
        for name, (_d, kind, desc) in TEMPLATES.items():
            t.add_row(name, kind, desc)
        console.print(t)
        info("dériver : [bold]new <modèle> <slug>[/bold] ou [bold]derive <existant> <slug>[/bold]")

    def complete_new(self, text, line, *_):
        return [k for k in TEMPLATES if k.startswith(text)] if len(line.split()) <= 2 else []

    def do_new(self, arg):
        "new <modèle> <slug> : crée un challenge ou une box depuis un modèle (web, tcp, static, box)."
        ev = self._need_event()
        args = self._args(arg)
        if not ev:
            return
        if len(args) != 2 or args[0] not in TEMPLATES:
            warn(f"usage : new <{'|'.join(TEMPLATES)}> <slug>")
            return
        tdir, kind, _ = TEMPLATES[args[0]]
        slug = slugify(args[1])
        dest = (ev.boxes_dir if kind == "box" else ev.challenges_dir) / slug
        if dest.exists():
            error(f"{dest} existe déjà")
            return
        shutil.copytree(TEMPLATES_DIR / tdir, dest)
        for p in dest.rglob("*"):
            if p.is_file():
                try:
                    txt = p.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                if "__SLUG__" in txt or "__BOX_NAME__" in txt:
                    p.write_text(txt.replace("__SLUG__", slug).replace("__BOX_NAME__", slug), encoding="utf-8")
        success(f"{kind} créé(e) : [cc.path]{dest}[/cc.path]")
        todo = {
            "challenge": "challenge.yml (nom, catégorie, flag), src/, solve.md, security-contract.yaml",
            "box": "box.yml, compose.yml, challenge/, challenge.yml (jalons + build_arg)",
        }[kind]
        info(f"à compléter : {todo}, puis [bold]check {slug}[/bold]")

    def do_derive(self, arg):
        "derive <existant> <nouveau> : copie un challenge ou une box comme base (flags remis en placeholder)."
        ev = self._need_event()
        args = self._args(arg)
        if not ev:
            return
        if len(args) != 2:
            warn("usage : derive <existant> <nouveau>")
            return
        src_name, new = args
        candidates = [ev.challenges_dir / src_name, ev.boxes_dir / src_name]
        src = next((c for c in candidates if c.is_dir()), None)
        if src is None:
            error(f"introuvable dans challenges/ ni boxes/ : {src_name}")
            return
        kind = "box" if src.parent == ev.boxes_dir else "challenge"
        try:
            dest = ev.derive(src, new, kind)
        except EventError as e:
            error(str(e))
            return
        success(f"{kind} dérivé(e) : [cc.path]{dest}[/cc.path] (flags remis en placeholder)")

    def complete_derive(self, text, *_):
        if not self.event:
            return []
        names = [p.name for p in self.event.challenge_dirs()] + [b.path.name for b in self.event.boxes()]
        return [n for n in names if n.startswith(text)]

    def do_list(self, arg):
        "list [--ctfd] : challenges et box de l'événement (--ctfd : état en ligne)."
        ev = self._need_event()
        if not ev:
            return
        with_ctfd = "--ctfd" in arg
        try:
            rows = ops.challenge_rows(ev, with_ctfd=with_ctfd, with_registry=shutil.which("docker") is not None)
        except SpecError as e:
            error(str(e))
            return
        t = Table(title=f"{ev.name} — {len(rows)} challenge(s) CTFd", title_style="bold")
        for col in ("Dossier", "Nom CTFd", "Type", "Catégorie", "Points", "Flags", "Image", "CTFd"):
            t.add_column(col, style="cyan" if col == "Dossier" else None, overflow="fold")
        for r in rows:
            short = r.image.rsplit("/", 1)[-1]
            img = "—" if r.type != "container" else (
                f"[cc.ok]✔[/] {short}" if r.in_registry else
                (f"[cc.ko]✘[/] {short}" if r.in_registry is False else f"[dim]{short}[/dim]"))
            flags = f"[cc.ok]{r.flags}[/]" if r.flags else "[cc.ko]0[/]"
            ctfd = {"visible": "[cc.state_visible]visible[/]", "hidden": "[cc.state_hidden]hidden[/]",
                    "absent": "[dim]absent[/dim]"}.get(r.ctfd, r.ctfd)
            t.add_row(r.slug, r.name, f"[cc.type]{r.type}[/]", r.category, r.points, flags, img, ctfd)
        if not rows:
            t.add_row("[dim]vide — new <modèle> <slug>[/dim]", *[""] * 7)
        console.print(t)
        boxes = ev.boxes()
        if boxes:
            b = Table(title="Box (labctl)", title_style="bold")
            for col in ("Box", "Titre", "Ports", "Flags de build", "État"):
                b.add_column(col, style="cyan" if col == "Box" else None)
            for x in boxes:
                b.add_row(x.name, x.title, ",".join(map(str, x.ports)), ", ".join(x.build_flags) or "—",
                          "[cc.ok]prête[/]" if not x.errors else f"[cc.ko]{len(x.errors)} erreur(s)[/]")
            console.print(b)

    def do_check(self, arg):
        "check [slug…] : format, préflight sécurité (contexte de build) et box."
        ev = self._need_event()
        if not ev:
            return None
        only = set(self._args(arg)) or None
        rep = ops.validate(ev, only)
        for w in rep.warnings:
            warn(escape(w))
        for e in rep.errors:
            error(escape(e))
        if rep.ok:
            success(f"{rep.challenges} challenge(s) et {rep.boxes} box : OK"
                    + (" — flags statiques autorisés" if ev.get("allow_static_flags") else ""))
        else:
            error(f"{len(rep.errors)} erreur(s) bloquante(s)")
        return rep

    # ------------------------------------------------------------------ déploiement

    def do_build(self, arg):
        "build [slug…] [--dry-run] [--no-cache] [--force] : build + push des images vers le registre."
        ev = self._need_event()
        if not ev:
            return 2
        args = self._args(arg)
        flags = {a for a in args if a.startswith("--")}
        only = [a for a in args if not a.startswith("--")] or None
        try:
            rc = ops.build_images(ev, only=only, dry_run="--dry-run" in flags,
                                  no_cache="--no-cache" in flags, force="--force" in flags)
        except ValueError as e:
            error(str(e))
            return 2
        (success if rc == 0 else error)(f"build terminé (code {rc})")
        return rc

    def _publish(self, only: set[str] | None, state: str | None, prune: bool, assume_yes: bool) -> bool:
        ev = self.event
        try:
            with console.status("[cyan]calcul du plan CTFd…[/cyan]"):
                p = ops.plan(ev, only=only, state=state, prune=prune)
        except (CTFdError, SpecError) as e:
            error(str(e))
            return False
        counts: dict[str, int] = {}
        for it in p.items:
            counts[it.action] = counts.get(it.action, 0) + 1
            if it.action in ("error", "warn", "create", "update", "del-flag", "del-tag", "del-hint", "del-file"):
                style = {"error": "cc.ko", "warn": "cc.warn", "create": "cc.ok", "update": "cc.keyword"}.get(
                    it.action, "cc.ko")
                console.print(f"  [{style}]{it.action:<8}[/] [bold]{escape(it.challenge)}[/bold] {escape(it.detail)}")
        info("plan : " + ", ".join(f"[bold]{k}[/bold]={v}" for k, v in sorted(counts.items())))
        if not p.ops:
            success("CTFd déjà à jour")
            return not p.errors
        if not assume_yes and not Confirm.ask(f"Appliquer {len(p.ops)} opération(s) sur {ev.get('ctfd_url')} ?",
                                              default=True):
            warn("annulé")
            return False
        failures = apply_plan(p, log=lambda m: step("[ÉCHEC]" not in m, escape(m.replace("[OK] ", "").replace(
            "[ÉCHEC] ", "").strip())))
        if failures or p.errors:
            error(f"{len(failures)} échec(s), {len(p.errors)} challenge(s) bloqué(s)")
            return False
        success(f"{len(p.ops)} opération(s) appliquée(s)")
        return True

    def do_publish(self, arg):
        "publish [slug…] [--prune] [-y] : publie dans CTFd (plan, confirmation, application)."
        if not self._need_event():
            return
        args = self._args(arg)
        only = {a for a in args if not a.startswith("-")} or None
        self._publish(only, None, "--prune" in args, "-y" in args)

    def do_open(self, arg):
        "open [slug…] [-y] : rend les challenges visibles aux participants."
        if self._need_event():
            args = self._args(arg)
            only = {a for a in args if not a.startswith("-")} or None
            self._publish(only, "visible", False, "-y" in args)

    def do_hide(self, arg):
        "hide [slug…] [-y] : masque les challenges (fin d'épreuve, maintenance)."
        if self._need_event():
            args = self._args(arg)
            only = {a for a in args if not a.startswith("-")} or None
            self._publish(only, "hidden", False, "-y" in args)

    def do_deploy(self, arg):
        "deploy [-y] : pipeline complet — contrôle, images, CTFd, box."
        ev = self._need_event()
        if not ev:
            return
        yes = "-y" in arg
        console.print(Panel(f"[bold]Déploiement[/bold] {ev.name} · version [cc.image]{ev.get('version')}[/] · "
                            f"CTFd {ev.get('ctfd_url')}", border_style="cyan"))
        total = 4
        with phase(1, total, "contrôle", "format · préflight · box") as ph:
            rep = self.do_check("")
            if not rep or not rep.ok:
                ph.fail("corriger les erreurs puis relancer")
        if not rep or not rep.ok:
            return
        with phase(2, total, "images", "build · push · vérification des digests") as ph:
            if ev.challenges_dir.is_dir() and any((d / "Dockerfile").is_file() for d in ev.challenge_dirs()):
                if self.do_build("") != 0:
                    ph.fail("voir la sortie du publisher")
            else:
                info("aucun challenge conteneur")
        if not ph.ok:
            return
        with phase(3, total, "ctfd", "challenges · flags · tags · hints · fichiers") as ph:
            if not os.environ.get("CTFD_TOKEN"):
                self.do_token("")
            if not self._publish(None, None, False, yes):
                ph.fail()
        if not ph.ok:
            return
        with phase(4, total, "box", "labctl · WireGuard · pare-feu") as ph:
            boxes = ev.boxes()
            if not boxes:
                info("aucune box")
            for box in boxes:
                n = 0 if yes else IntPrompt.ask(f"Instances à déployer pour [cyan]{box.name}[/cyan] (0 = plus tard)",
                                                default=0)
                if n > 0:
                    self._labctl(f"use {box.name}")
                    self._labctl(f"deploy {n}")
            if boxes:
                info("configs VPN : [bold]box wg all[/bold] · instances : [bold]box list[/bold]")
        success(f"{ev.name} déployé. Ouverture aux participants : [bold]open[/bold]")

    # ------------------------------------------------------------------ labctl

    def _labctl(self, line: str, quiet: bool = False) -> None:
        try:
            from labctl.ui import LabctlShell
        except ImportError:
            if not quiet:
                error("labctl non installé (pip install -e . depuis CTFCreator)")
            return
        if self.event:
            self._bind_labs()
        if quiet and line.split()[:1] == ["list"] and not (self.event and self.event.boxes()):
            return
        LabctlShell().onecmd(line)

    def do_box(self, arg):
        "box <commande labctl> : use, add, deploy <n>, list, wg <user>|all, endpoint <ip>, firewall, destroy."
        if not self._need_event():
            return
        if not arg.strip():
            self._labctl("help")
            return
        self._labctl(arg)

    def do_labs(self, _arg):
        "labs : ouvre le shell labctl sur les box de l'événement (exit pour revenir)."
        if not self._need_event():
            return
        self._bind_labs()
        from labctl.discovery import discover_boxes
        from labctl.ui import LabctlShell, boxes_table

        console.print(boxes_table(discover_boxes()))
        try:
            LabctlShell().cmdloop()
        except KeyboardInterrupt:
            console.print()
        self._refresh_prompt()

    # ------------------------------------------------------------------ session

    def do_token(self, _arg):
        "token : saisit le jeton admin CTFd (masqué, gardé en mémoire pour la session)."
        tok = getpass.getpass("Jeton admin CTFd (Settings → Access Tokens) : ").strip()
        if not tok:
            warn("jeton vide, inchangé")
            return
        os.environ["CTFD_TOKEN"] = tok
        self._refresh_prompt()
        if self.event:
            try:
                n = len(ops.client(self.event).challenges())
                success(f"jeton valide : {n} challenge(s) en ligne sur {self.event.get('ctfd_url')}")
            except CTFdError as e:
                error(f"jeton refusé : {e}")

    def do_clear(self, _arg):
        "clear : efface l'écran."
        console.clear()

    def do_exit(self, _arg):
        "exit : quitte."
        console.print("[dim]à bientôt.[/dim]")
        return True

    do_quit = do_exit

    def do_EOF(self, _arg):
        console.print()
        return True

    def emptyline(self):
        return False

    def default(self, line):
        error(f"commande inconnue : {line} — tape [bold]help[/bold]")

    def postcmd(self, stop, line):
        self._refresh_prompt()
        return stop


def interactive(workspace: Path | None = None, event_path: Path | None = None) -> int:
    console.print(banner(__version__))
    ev = None
    if event_path:
        try:
            ev = Event.load(event_path)
        except EventError as e:
            error(str(e))
    sh = CTFCreatorShell(workspace, ev)
    info(f"workspace : [cc.path]{sh.workspace}[/cc.path]  (variable CTFCREATOR_EVENTS)")
    if ev:
        success(f"événement : [bold]{ev.name}[/bold]")
    else:
        sh.do_events("")
    try:
        sh.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]interrompu.[/dim]")
    return 0
