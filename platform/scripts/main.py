#!/usr/bin/env python3
"""Point d'entrée opérationnel course-ctfd-infra."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import build_context, print_status  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="course-ctfd-infra",
        description=(
            "Préparation VPS de cours et déploiement CTFd (mode degraded par défaut). "
            "Aucune action destructive sans confirmation."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Affiche les actions sans les exécuter",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirme les actions destructives explicitement documentées",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("preflight", help="Inventaire en lecture seule")
    sub.add_parser("backup", help="Sauvegarde configs/volumes/DB")

    p_ssh = sub.add_parser("harden-ssh", help="Durcissement SSH progressif")
    p_ssh.add_argument(
        "--pubkey",
        help="Clé publique OpenSSH (une ligne : ssh-ed25519 AAAA…)",
    )
    p_ssh.add_argument(
        "--pubkey-file",
        help="Fichier .pub à installer pour ADMIN_SSH_USER",
    )
    p_ssh.add_argument(
        "--identity",
        help=(
            "Clé privée locale pour tester une nouvelle connexion après reload "
            "(optionnel ; sinon confirmation manuelle d'une 2e session)"
        ),
    )

    sub.add_parser("configure-firewall", help="Pare-feu (nftables ou ufw)")
    sub.add_parser("deploy", help="Déploie CTFd (degraded si plugin non conforme)")
    sub.add_parser("verify", help="Vérifications fonctionnelles")
    sub.add_parser("vendor-theme", help="Re-télécharge themes/pixo au commit épinglé")
    sub.add_parser(
        "vendor-plugin-docker",
        help="Re-télécharge plugins/challenge_containers (0xfbad, commit épinglé)",
    )

    p_rb = sub.add_parser("rollback", help="Retour arrière contrôlé")
    p_rb.add_argument(
        "--target",
        choices=["all", "ssh", "firewall", "ctfd"],
        default="all",
        help="Cible de rollback",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ctx = build_context(dry_run=args.dry_run, assume_yes=args.yes)

    print_status("INFO", f"Commande={args.command} dry_run={ctx.dry_run} yes={ctx.assume_yes}")

    if args.command == "preflight":
        from preflight import run_preflight

        return run_preflight(ctx)
    if args.command == "backup":
        from backup import run_backup

        return run_backup(ctx)
    if args.command == "harden-ssh":
        from harden_ssh import run_harden_ssh

        return run_harden_ssh(
            ctx,
            pubkey=getattr(args, "pubkey", None),
            pubkey_file=getattr(args, "pubkey_file", None),
            identity_file=getattr(args, "identity", None),
        )
    if args.command == "configure-firewall":
        from firewall import run_configure_firewall

        return run_configure_firewall(ctx)
    if args.command == "deploy":
        from deploy import run_deploy

        return run_deploy(ctx)
    if args.command == "verify":
        from verify import run_verify

        return run_verify(ctx)
    if args.command == "vendor-theme":
        from vendor_assets import vendor_theme

        return vendor_theme(ctx)
    if args.command == "vendor-plugin-docker":
        from vendor_assets import vendor_plugin_docker

        return vendor_plugin_docker(ctx)
    if args.command == "rollback":
        from rollback import run_rollback

        return run_rollback(ctx, target=args.target)

    parser.error(f"Commande inconnue : {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
