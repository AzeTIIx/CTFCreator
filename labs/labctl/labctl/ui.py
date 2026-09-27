"""Rendu Rich + shell interactif à la GOAD (REPL de commandes).

On tape des commandes (`use`, `list`, `add`, `deploy`, `wg <user>`, ...),
pas des numéros. Le vocabulaire est « user » (utilisateur).
"""

from __future__ import annotations

import cmd
import shutil

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import deploy as dep
from . import service, state, wireguard
from .discovery import discover_boxes, get_box
from .model import Box, Deployment, LabctlError

console = Console()

BANNER = r"""
 _       _     ___ _____ _
| | __ _| |__ / __\_   _| |    orchestrateur de box (lab)
| |/ _` | '_ \ (__  | | | |    accès WireGuard · isolation nftables
| | (_| | |_) \__ \ | | | |___ déploiement batch par user
|_|\__,_|_.__/|___/ |_| |____|
"""


def banner() -> Panel:
    return Panel(Align.center(Text(BANNER, style="bold cyan")),
                 border_style="cyan", subtitle="[dim]labctl — tape 'help'[/dim]")


def tool_line() -> Text:
    def mark(name, ok):
        return f"[green]{name} OK[/green]" if ok else f"[red]{name} absent[/red]"
    docker = shutil.which("docker") is not None
    wg = wireguard.wg_available()
    ipt = shutil.which("iptables") is not None
    t = Text.from_markup(f"outils : {mark('docker', docker)}  {mark('wg', wg)}  {mark('iptables', ipt)}")
    if not (docker and wg and ipt):
        t.append("   (déploiement réel = sur la Debian)", style="yellow")
    return t


def boxes_table(boxes: list[Box]) -> Table:
    t = Table(title="Box disponibles", title_style="bold")
    t.add_column("Box", style="cyan"); t.add_column("Titre")
    t.add_column("Entrée"); t.add_column("Ports"); t.add_column("Flags", justify="right")
    for b in boxes:
        t.add_row(b.name, b.title or "—", b.entry_service,
                  ",".join(map(str, b.ports)), str(len(b.flags)))
    if not boxes:
        t.add_row("[dim]aucune box[/dim]", "", "", "", "")
    return t


def users_table(deploy: Deployment, boxes: dict[str, Box], live: bool) -> Table:
    t = Table(title="Users déployés", title_style="bold")
    t.add_column("#", justify="right", style="dim"); t.add_column("Box", style="cyan")
    t.add_column("User"); t.add_column("IP cible"); t.add_column("IP VPN")
    t.add_column("Bridge")
    if live:
        t.add_column("État")
    for inst in sorted(deploy.instances, key=lambda x: x.index):
        row = [str(inst.index), inst.box, inst.user, inst.entry_ip, inst.wg_peer_ip, inst.bridge_name]
        if live:
            box = boxes.get(inst.box)
            up = dep.is_up(box, inst) if box else False
            row.append("[green]up[/green]" if up else "[red]down[/red]")
        t.add_row(*row)
    if not deploy.instances:
        t.add_row(*(["[dim]—[/dim]"] * (7 if live else 6)))
    return t


def _reconcile() -> None:
    """Applique automatiquement l'état hôte (WireGuard serveur + pare-feu)."""
    for r in service.reconcile_host(state.load_deployment()):
        color = "green" if r.ok else "yellow"
        console.print(f"  [{color}]{'OK' if r.ok else '· '}[/] {r.label} {r.detail}")


class LabctlShell(cmd.Cmd):
    intro = ""
    doc_header = "Commandes (help <cmd> pour le détail)"

    def __init__(self):
        super().__init__()
        state.ensure_dirs()
        self.settings = state.load_settings()
        self.active_box: str | None = self.settings.get("active_box")
        self._refresh_prompt()

    # --- helpers ----------------------------------------------------------
    def _boxes(self) -> list[Box]:
        return discover_boxes()

    def _boxes_map(self) -> dict[str, Box]:
        return {b.name: b for b in self._boxes()}

    def _deploy(self) -> Deployment:
        return state.load_deployment()

    def _refresh_prompt(self) -> None:
        box = self.active_box or "-"
        self.prompt = f"\001\033[1;36m\002labctl(\001\033[0m\002{box}\001\033[1;36m\002)>\001\033[0m\002 "

    def _need_box(self) -> Box | None:
        if not self.active_box:
            console.print("[yellow]Aucune box active. Fais d'abord : use <box>[/yellow]")
            return None
        try:
            return get_box(self.active_box)
        except LabctlError as e:
            console.print(f"[red]{e}[/red]")
            return None

    def _save_settings(self) -> None:
        self.settings["active_box"] = self.active_box
        state.save_settings(self.settings)

    # --- commandes --------------------------------------------------------
    def do_boxes(self, _arg):
        "boxes : liste les box disponibles."
        console.print(boxes_table(self._boxes()))

    def do_use(self, arg):
        "use <box> : sélectionne la box active."
        name = arg.strip()
        try:
            box = get_box(name)
        except LabctlError as e:
            console.print(f"[red]{e}[/red]"); return
        self.active_box = box.name
        self._save_settings(); self._refresh_prompt()
        console.print(f"[green]box active :[/green] {box.name}")

    def complete_use(self, text, *_):
        return [b.name for b in self._boxes() if b.name.startswith(text)]

    def do_list(self, _arg):
        "list : liste les users déployés (avec état live si docker présent)."
        console.print(users_table(self._deploy(), self._boxes_map(),
                                  live=shutil.which("docker") is not None))
    do_users = do_list
    do_status = do_list

    def do_add(self, arg):
        "add <user> [<user>...] : alloue un ou plusieurs users sur la box active (sans déployer)."
        box = self._need_box()
        if not box:
            return
        names = arg.split()
        if not names:
            console.print("[yellow]usage : add <user> [<user>...][/yellow]"); return
        deploy = self._deploy()
        service.add_users(deploy, box, names)
        console.print(users_table(deploy, self._boxes_map(), live=False))

    def do_deploy(self, arg):
        "deploy [<n>|<user>|all] : construit+lance. 'deploy 5' crée user01..user05 ; 'deploy all' déploie tous les users alloués de la box ; 'deploy <user>' un seul."
        box = self._need_box()
        if not box:
            return
        deploy = self._deploy()
        arg = arg.strip()
        if arg.isdigit():
            start = len(deploy.for_box(box.name)) + 1
            labels = [f"user{i:02d}" for i in range(start, start + int(arg))]
            targets = service.add_users(deploy, box, labels)
        elif arg in ("", "all"):
            targets = deploy.for_box(box.name)
        else:
            targets = [service.add_users(deploy, box, [arg])[0]]
        if not targets:
            console.print("[yellow]rien à déployer (add <user> d'abord, ou deploy <n>)[/yellow]"); return
        if not shutil.which("docker"):
            console.print("[yellow]docker absent — users alloués, déploiement à faire sur la Debian.[/yellow]")
            console.print(users_table(deploy, self._boxes_map(), live=False)); return
        with console.status("[cyan]déploiement…[/cyan]"):
            for step in service.deploy_instances(box, targets):
                console.print(f"  [{'green' if step.ok else 'red'}]{'OK' if step.ok else 'KO'}[/] {step.label} {step.detail}")
        _reconcile()

    def do_endpoint(self, arg):
        "endpoint <ip> : IP publique du VPS (pour les configs WireGuard). Sans argument, affiche."
        arg = arg.strip()
        if not arg:
            console.print(f"endpoint : {self.settings.get('endpoint') or '[dim]non défini[/dim]'}"); return
        self.settings["endpoint"] = arg
        state.save_settings(self.settings)
        console.print(f"[green]endpoint :[/green] {arg}")

    def do_wg(self, arg):
        "wg <user>|all : génère et affiche la config WireGuard d'un user (ou régénère tout)."
        deploy = self._deploy()
        endpoint = self.settings.get("endpoint")
        if not endpoint:
            console.print("[yellow]endpoint non défini. Fais : endpoint <ip_publique_vps>[/yellow]"); return
        if not wireguard.wg_available():
            console.print("[yellow]binaire `wg` absent — à exécuter sur la Debian.[/yellow]"); return
        res = service.write_wireguard(deploy, endpoint)
        arg = arg.strip()
        if arg in ("", "all"):
            t = Table("User (projet)", "Profil .conf", title="Configs WireGuard")
            for proj, path in res["clients"].items():
                t.add_row(proj, str(path))
            console.print(t)
            console.print(f"[dim]Serveur : {res['server']}[/dim]")
            return
        inst = deploy.find(self.active_box, arg) if self.active_box else None
        if inst is None:
            inst = next((i for i in deploy.instances if i.user == arg), None)
        if inst is None:
            console.print(f"[red]user inconnu : {arg}[/red]"); return
        path = res["clients"].get(inst.project)
        # Texte BRUT (pas de Panel) pour un copier-coller propre ; le chemin
        # est en commentaire (le fichier est aussi sur disque, à scp/distribuer).
        console.print(f"[dim]# {inst.user} · {path}[/dim]")
        print(path.read_text(encoding="utf-8"))
    do_wireguard = do_wg

    def complete_wg(self, text, *_):
        return [i.user for i in self._deploy().instances if i.user.startswith(text)]
    complete_wireguard = complete_wg

    def do_firewall(self, arg):
        "firewall [apply] : génère le script de cloisonnement (et l'applique si 'apply' + root)."
        deploy = self._deploy()
        path = service.write_firewall_script(deploy)
        console.print(f"[green]script généré :[/green] {path}")
        if arg.strip() == "apply":
            if not shutil.which("iptables"):
                console.print("[yellow]iptables absent — applique sur la Debian.[/yellow]"); return
            r = service.apply_firewall(deploy)
            console.print(r.stdout or r.stderr)
        else:
            console.print("[dim]applique en root : sudo bash <script>  (ou lab-firewall.service)[/dim]")

    def do_destroy(self, arg):
        "destroy <user> : détruit l'instance d'un user (down + retrait de l'état)."
        arg = arg.strip()
        deploy = self._deploy()
        inst = None
        if self.active_box:
            inst = deploy.find(self.active_box, arg)
        if inst is None:
            inst = next((i for i in deploy.instances if i.user == arg), None)
        if inst is None:
            console.print(f"[red]user inconnu : {arg}[/red]"); return
        try:
            box = get_box(inst.box)
        except LabctlError:
            box = None
        if box and shutil.which("docker"):
            r = service.destroy_instance(deploy, box, inst)
            console.print(f"[{'green' if r.ok else 'red'}]{'OK' if r.ok else 'KO'}[/] {r.label} {r.detail}")
        else:
            deploy.remove(inst.box, inst.user); service.save(deploy)
            console.print("[green]retiré de l'état (docker absent).[/green]")
        _reconcile()

    def complete_destroy(self, text, *_):
        return [i.user for i in self._deploy().instances if i.user.startswith(text)]

    def do_new(self, arg):
        "new <slug> : crée une nouvelle box depuis le template."
        from .scaffold import scaffold_box
        try:
            path = scaffold_box(arg.strip())
            console.print(f"[green]box créée :[/green] {path}")
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]{e}[/red]")

    def do_exit(self, _arg):
        "exit : quitte."
        console.print("[dim]à bientôt.[/dim]"); return True
    do_quit = do_exit

    def do_EOF(self, _arg):
        console.print(); return True

    def emptyline(self):
        return False

    def default(self, line):
        console.print(f"[red]commande inconnue : {line}[/red] — tape [bold]help[/bold]")


def interactive() -> None:
    console.print(banner())
    console.print(tool_line())
    console.print(boxes_table(discover_boxes()))
    console.print(users_table(state.load_deployment(),
                              {b.name: b for b in discover_boxes()}, live=False))
    try:
        LabctlShell().cmdloop()
    except KeyboardInterrupt:
        console.print("\n[dim]interrompu.[/dim]")
