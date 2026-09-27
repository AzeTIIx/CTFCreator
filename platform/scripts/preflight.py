"""Prévol en lecture seule — inventaire hôte sans modification."""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

# Permet l'import depuis scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    AppContext,
    build_context,
    is_linux,
    print_status,
    redact_text,
    require_for_deploy,
    run_cmd,
    utc_now,
    validate_image_ref,
    validate_port,
    which,
    write_report,
)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def detect_distro() -> dict[str, Any]:
    info: dict[str, Any] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    os_release = _read_text(Path("/etc/os-release"))
    if os_release:
        parsed: dict[str, str] = {}
        for line in os_release.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                parsed[k] = v.strip().strip('"')
        info["os_release"] = {
            "id": parsed.get("ID"),
            "version_id": parsed.get("VERSION_ID"),
            "pretty_name": parsed.get("PRETTY_NAME"),
        }
    else:
        info["os_release"] = None
        info["note"] = "Pas de /etc/os-release (hôte non Linux ou inaccessible)"
    return info


def detect_resources() -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        usage = shutil.disk_usage(Path.cwd().anchor if not is_linux() else "/")
        out["disk"] = {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "free_gb": round(usage.free / (1024**3), 2),
        }
    except OSError as exc:
        out["disk"] = {"error": str(exc)}

    if is_linux():
        meminfo = _read_text(Path("/proc/meminfo"))
        if meminfo:
            mem: dict[str, int] = {}
            for line in meminfo.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    num = v.strip().split()[0]
                    try:
                        mem[k] = int(num)
                    except ValueError:
                        pass
            out["memory_kib"] = {
                "MemTotal": mem.get("MemTotal"),
                "MemAvailable": mem.get("MemAvailable"),
            }
        cpu = _read_text(Path("/proc/cpuinfo"))
        if cpu:
            out["cpu_count_logical"] = cpu.count("processor\t:")
        pids_max = _read_text(Path("/proc/sys/kernel/pid_max"))
        out["pid_max"] = pids_max
    else:
        out["memory"] = "non disponible hors Linux (prévol local limité)"
        out["cpu_count_logical"] = os.cpu_count()
    return out


def detect_user() -> dict[str, Any]:
    data: dict[str, Any] = {
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "uid": getattr(os, "getuid", lambda: None)(),
        "gid": getattr(os, "getgid", lambda: None)(),
        "euid": getattr(os, "geteuid", lambda: None)(),
        "is_root": False,
    }
    if data["euid"] == 0:
        data["is_root"] = True
    if which("sudo"):
        # Lecture seule : ne pas exécuter sudo -n de manière intrusive si dry
        data["sudo_present"] = True
    else:
        data["sudo_present"] = False
    return data


def detect_docker(ctx: AppContext) -> dict[str, Any]:
    info: dict[str, Any] = {"docker_bin": which("docker")}
    if not info["docker_bin"]:
        info["installed"] = False
        return info
    info["installed"] = True
    ver = run_cmd(ctx, ["docker", "version", "--format", "{{.Server.Version}}"])
    info["server_version"] = ver.stdout.strip() if ver.ok else None
    info["server_error"] = ver.stderr.strip() if not ver.ok else None
    compose = run_cmd(ctx, ["docker", "compose", "version"])
    info["compose"] = compose.stdout.strip() if compose.ok else None
    # Services existants (noms seulement)
    ps = run_cmd(ctx, ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"])
    if ps.ok:
        info["running_containers"] = [
            line for line in ps.stdout.splitlines() if line.strip()
        ]
    return info


def detect_firewall(ctx: AppContext) -> dict[str, Any]:
    info: dict[str, Any] = {"ufw": None, "nftables": None, "iptables": None, "chosen": None}
    if which("ufw"):
        r = run_cmd(ctx, ["ufw", "status"])
        info["ufw"] = {"present": True, "status": r.stdout.strip() if r.ok else r.stderr.strip()}
    else:
        info["ufw"] = {"present": False}
    if which("nft"):
        r = run_cmd(ctx, ["nft", "list", "ruleset"])
        # Ne pas stocker un dump énorme : seulement présence / longueur
        info["nftables"] = {
            "present": True,
            "ruleset_bytes": len(r.stdout) if r.ok else 0,
            "readable": r.ok,
        }
    else:
        info["nftables"] = {"present": False}
    if which("iptables"):
        info["iptables"] = {"present": True}
    # Choix : ne pas installer ; recommander selon présence
    if info["ufw"]["present"] and "Status: active" in str(info["ufw"].get("status", "")):
        info["chosen"] = "ufw"
    elif info["nftables"]["present"]:
        info["chosen"] = "nftables"
    elif info["ufw"]["present"]:
        info["chosen"] = "ufw"
    else:
        info["chosen"] = "none_detected"
    return info


def detect_ssh(ctx: AppContext) -> dict[str, Any]:
    info: dict[str, Any] = {
        "configured_port": (ctx.env.get("SSH_PORT") or "22"),
        "sshd_present": bool(which("sshd") or Path("/usr/sbin/sshd").exists()),
    }
    if not validate_port(str(info["configured_port"])):
        info["port_valid"] = False
    else:
        info["port_valid"] = True

    # Port effectivement en écoute (Linux)
    if is_linux() and Path("/proc/net/tcp").exists():
        listening = []
        ss = which("ss")
        if ss:
            r = run_cmd(ctx, ["ss", "-ltnp"])
            if r.ok:
                for line in r.stdout.splitlines():
                    if ":22 " in line or f":{info['configured_port']} " in line:
                        listening.append(line.strip())
        info["listening_hints"] = listening
    else:
        info["listening_hints"] = "non déterminé hors Linux cible"

    # Session SSH active ?
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT"):
        info["active_ssh_session"] = True
        # Ne pas logger l'IP complète de SSH_CLIENT si sensible — garder booléen + longueur
        info["ssh_connection_present"] = True
    else:
        info["active_ssh_session"] = False
        info["ssh_connection_present"] = False
    return info


def detect_services(ctx: AppContext) -> dict[str, Any]:
    services: dict[str, Any] = {"systemd": False, "units_sample": []}
    if which("systemctl"):
        services["systemd"] = True
        r = run_cmd(
            ctx,
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-pager",
                "--no-legend",
            ],
        )
        if r.ok:
            lines = [ln.split()[0] for ln in r.stdout.splitlines() if ln.strip()]
            services["running_count"] = len(lines)
            # Échantillon limité (noms uniquement)
            services["units_sample"] = lines[:40]
            sensitive = [
                u
                for u in lines
                if any(
                    x in u
                    for x in (
                        "nginx",
                        "apache",
                        "mysql",
                        "mariadb",
                        "postgres",
                        "docker",
                        "ctfd",
                        "traefik",
                        "caddy",
                    )
                )
            ]
            services["relevant_units"] = sensitive
    return services


def detect_certs_proxy() -> dict[str, Any]:
    paths = [
        Path("/etc/nginx"),
        Path("/etc/caddy"),
        Path("/etc/traefik"),
        Path("/etc/letsencrypt"),
        Path("/etc/ssl/certs"),
    ]
    found = []
    for p in paths:
        if p.exists():
            found.append(str(p))
    return {"existing_proxy_or_cert_paths": found}


def detect_dns(ctx: AppContext) -> dict[str, Any]:
    fqdn = (ctx.env.get("CTFD_FQDN") or "").strip()
    result: dict[str, Any] = {"fqdn": fqdn or None, "resolved": False, "addresses": []}
    if not fqdn or "example.invalid" in fqdn:
        result["note"] = "CTFD_FQDN manquant ou valeur d'exemple"
        return result
    try:
        infos = socket.getaddrinfo(fqdn, None)
        addrs = sorted({item[4][0] for item in infos})
        result["addresses"] = addrs
        result["resolved"] = bool(addrs)
    except socket.gaierror as exc:
        result["error"] = str(exc)
    return result


def detect_clock(ctx: AppContext) -> dict[str, Any]:
    info: dict[str, Any] = {"utc_local_view": utc_now()}
    if which("timedatectl"):
        r = run_cmd(ctx, ["timedatectl", "status"])
        if r.ok:
            # Extraire lignes non sensibles
            lines = [
                ln.strip()
                for ln in r.stdout.splitlines()
                if any(
                    k in ln
                    for k in (
                        "System clock synchronized",
                        "NTP",
                        "Time zone",
                        "synchronized",
                    )
                )
            ]
            info["timedatectl"] = lines
    return info


def detect_backup_availability(ctx: AppContext) -> dict[str, Any]:
    backup_root = Path(ctx.env.get("BACKUP_ROOT") or "/var/backups/course-ctfd")
    local_backups = ctx.root / "backups"
    return {
        "configured_backup_root": str(backup_root),
        "backup_root_exists": backup_root.exists(),
        "local_backups_dir_exists": local_backups.exists(),
        "local_backup_count": len(list(local_backups.glob("*"))) if local_backups.exists() else 0,
        "note": "Une sauvegarde doit exister avant toute modification destructive.",
    }


def validate_declared_images(ctx: AppContext) -> dict[str, Any]:
    keys = [
        "CTFD_IMAGE",
        "MARIADB_IMAGE",
        "REDIS_IMAGE",
        "NGINX_IMAGE",
        "ALPINE_IMAGE",
        "REGISTRY_IMAGE",
    ]
    results = {}
    for key in keys:
        ref = ctx.env.get(key, "")
        results[key] = {"value": ref, "valid_pinned": validate_image_ref(ref)}
    return results


def run_preflight(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    print_status("INFO", "Prévol en lecture seule — aucune modification système")

    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "mode": "read_only",
        "distro": detect_distro(),
        "user": detect_user(),
        "resources": detect_resources(),
        "docker": detect_docker(ctx),
        "firewall": detect_firewall(ctx),
        "ssh": detect_ssh(ctx),
        "services": detect_services(ctx),
        "certs_proxy": detect_certs_proxy(),
        "dns": detect_dns(ctx),
        "clock": detect_clock(ctx),
        "backups": detect_backup_availability(ctx),
        "images": validate_declared_images(ctx),
        "ssh_firewall_policy": "any (pas de ADMIN_CIDR — admin mobile)",
    }

    missing = require_for_deploy(ctx.env)
    report["missing_for_deploy"] = missing
    report["deploy_blocked"] = bool(missing) or not is_linux()
    report["target_is_linux"] = is_linux()
    report["plugin_selection"] = ctx.env.get("PLUGIN_SELECTION", "none")
    report["deploy_mode"] = ctx.env.get("DEPLOY_MODE", "degraded")

    if not is_linux():
        report["honest_status"] = (
            "Prévol exécuté hors cible Linux (environnement de développement). "
            "Aucun durcissement SSH, pare-feu ou déploiement CTFd n'a été appliqué."
        )
        print_status("WARN", report["honest_status"])

    if missing:
        print_status(
            "WARN",
            "Variables manquantes ou encore à l'état d'exemple : " + ", ".join(missing),
        )
        print_status(
            "INFO",
            "Créer un fichier .env à partir de .env.example avec les valeurs réelles du VPS.",
        )

    # Images latest interdites
    bad_images = [
        k for k, v in report["images"].items() if not v.get("valid_pinned")
    ]
    if bad_images:
        print_status("FAIL", f"Références d'images non conformes : {', '.join(bad_images)}")
        report["deploy_blocked"] = True

    path = write_report(ctx, "preflight", report)
    print_status("OK", f"Rapport prévol écrit : {path.name}")

    # Code de sortie : 0 si prévol OK (même si deploy bloqué), 2 si inventaire critique incomplet
    if bad_images:
        return 2
    if missing:
        print_status("INFO", "Prévol terminé — déploiement bloqué jusqu'à configuration complète")
        return 0
    if not is_linux():
        return 0
    print_status("OK", "Prévol Linux cible complété")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_preflight())
