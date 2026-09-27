"""Entrée labctl : shell interactif par défaut, sous-commandes pour le batch.

  python -m labctl                       # shell interactif (REPL à la GOAD)
  python -m labctl list
  python -m labctl deploy <box> -n 5      # crée user01..user05 et déploie
  python -m labctl wireguard <box> [user] --endpoint <ip>
  python -m labctl firewall [--apply]
  python -m labctl status
  python -m labctl destroy --user <name>
  python -m labctl new <slug>
"""

from __future__ import annotations

import argparse
import shutil
import sys

from . import service, state
from .discovery import discover_boxes, get_box
from .ui import boxes_table, console, interactive, users_table


def _boxes_map():
    return {b.name: b for b in discover_boxes()}


def cmd_list(_args) -> int:
    console.print(boxes_table(discover_boxes()))
    console.print(users_table(state.load_deployment(), _boxes_map(),
                              live=shutil.which("docker") is not None))
    return 0


def cmd_status(_args) -> int:
    console.print(users_table(state.load_deployment(), _boxes_map(),
                              live=shutil.which("docker") is not None))
    return 0


def cmd_deploy(args) -> int:
    deploy = state.load_deployment()
    box = get_box(args.box)
    start = len(deploy.for_box(box.name)) + 1
    labels = [f"{args.prefix}{i:02d}" for i in range(start, start + args.number)]
    made = service.add_users(deploy, box, labels)
    console.print(users_table(deploy, _boxes_map(), live=False))
    if not shutil.which("docker"):
        console.print("[yellow]docker absent — users alloués seulement.[/yellow]")
        return 0
    rc = 0
    for step in service.deploy_instances(box, made, no_cache=args.no_cache):
        console.print(f"  [{'green' if step.ok else 'red'}]{'OK' if step.ok else 'KO'}[/] {step.label} {step.detail}")
        rc = rc or (0 if step.ok else 1)
    for r in service.reconcile_host(state.load_deployment()):
        console.print(f"  [{'green' if r.ok else 'yellow'}]{'OK' if r.ok else '·'}[/] {r.label} {r.detail}")
    return rc


def cmd_wireguard(args) -> int:
    settings = state.load_settings()
    if args.endpoint:
        settings["endpoint"] = args.endpoint
        state.save_settings(settings)
    endpoint = settings.get("endpoint")
    if not endpoint:
        console.print("[red]endpoint requis : --endpoint <ip> (persisté ensuite)[/red]")
        return 2
    deploy = state.load_deployment()
    res = service.write_wireguard(deploy, endpoint)
    if args.user:
        inst = next((i for i in deploy.instances if i.user == args.user), None)
        if not inst:
            console.print(f"[red]user inconnu : {args.user}[/red]"); return 2
        path = res["clients"][inst.project]
        print(path.read_text(encoding="utf-8"))   # brut, copier-coller propre
    else:
        console.print(f"[green]wg0.conf :[/green] {res['server']}")
        for proj, path in res["clients"].items():
            console.print(f"  {proj} -> {path}")
    return 0


def cmd_firewall(args) -> int:
    deploy = state.load_deployment()
    path = service.write_firewall_script(deploy)
    console.print(f"[green]script :[/green] {path}")
    if args.apply:
        r = service.apply_firewall(deploy)
        console.print(r.stdout or r.stderr)
        return r.returncode
    return 0


def cmd_destroy(args) -> int:
    deploy = state.load_deployment()
    inst = next((i for i in deploy.instances if i.user == args.user), None)
    if not inst:
        console.print("[red]user inconnu[/red]"); return 2
    box = get_box(inst.box)
    r = service.destroy_instance(deploy, box, inst)
    console.print(f"[{'green' if r.ok else 'red'}]{'OK' if r.ok else 'KO'}[/] {r.label} {r.detail}")
    for rr in service.reconcile_host(state.load_deployment()):
        console.print(f"  [{'green' if rr.ok else 'yellow'}]{'OK' if rr.ok else '·'}[/] {rr.label} {rr.detail}")
    return 0 if r.ok else 1


def cmd_new(args) -> int:
    from .scaffold import scaffold_box
    console.print(f"[green]box créée :[/green] {scaffold_box(args.slug)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="labctl", description="Orchestrateur de box (lab).")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("list").set_defaults(func=cmd_list)
    sub.add_parser("status").set_defaults(func=cmd_status)
    d = sub.add_parser("deploy"); d.add_argument("box"); d.add_argument("-n", "--number", type=int, default=1)
    d.add_argument("--prefix", default="user"); d.add_argument("--no-cache", action="store_true")
    d.set_defaults(func=cmd_deploy)
    w = sub.add_parser("wireguard"); w.add_argument("user", nargs="?")
    w.add_argument("--endpoint"); w.set_defaults(func=cmd_wireguard)
    f = sub.add_parser("firewall"); f.add_argument("--apply", action="store_true"); f.set_defaults(func=cmd_firewall)
    x = sub.add_parser("destroy"); x.add_argument("--user", required=True); x.set_defaults(func=cmd_destroy)
    n = sub.add_parser("new"); n.add_argument("slug"); n.set_defaults(func=cmd_new)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state.ensure_dirs()
    if not getattr(args, "cmd", None):
        interactive()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
