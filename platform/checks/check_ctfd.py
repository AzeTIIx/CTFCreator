"""Contrôles CTFd — santé HTTP réelle, pas seulement processus."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import AppContext, is_linux, print_status, run_cmd, which  # noqa: E402

CHECK_CTFD_REVISION = "2026-09-14-c"


def _compose_runtime_env(ctx: AppContext) -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "CTFD_IMAGE",
        "MARIADB_IMAGE",
        "REDIS_IMAGE",
        "NGINX_IMAGE",
        "ALPINE_IMAGE",
        "DB_ROOT_PASSWORD",
        "DB_PASSWORD",
        "REDIS_PASSWORD",
        "SECRET_KEY",
        "CTFD_WORKERS",
        "CTFD_MEMORY_LIMIT",
        "CTFD_CPU_LIMIT",
        "DB_MEMORY_LIMIT",
        "CACHE_MEMORY_LIMIT",
        "NGINX_MEMORY_LIMIT",
        "COMPOSE_PROJECT_NAME",
    ):
        if ctx.env.get(key):
            env[key] = ctx.env[key]
    return env


def _infer_service(name: str, project: str, label_service: str) -> str:
    if label_service:
        return label_service
    prefix = f"{project}-"
    if name.startswith(prefix):
        rest = name[len(prefix):]
        m = re.match(r"^(.+)-\d+$", rest)
        if m:
            return m.group(1)
    return ""


def _list_project_containers(ctx: AppContext, project: str) -> list[dict[str, str]]:
    containers: list[dict[str, str]] = []
    seen: set[str] = set()
    queries = [
        ["docker", "ps", "-a", "--filter", f"name={project}", "--format",
         "{{.Names}}\t{{.Status}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Ports}}"],
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format",
         "{{.Names}}\t{{.Status}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Ports}}"],
    ]
    for argv in queries:
        r = run_cmd(ctx, argv)
        if not r.ok:
            continue
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            if not name or name in seen:
                continue
            label_svc = parts[2].strip() if len(parts) > 2 else ""
            if not (name.startswith(f"{project}-") or name.startswith(f"{project}_") or label_svc):
                continue
            seen.add(name)
            containers.append({
                "name": name,
                "status": parts[1].strip(),
                "service": _infer_service(name, project, label_svc),
                "ports": parts[3].strip() if len(parts) > 3 else "",
            })
    return containers


def _is_running(status: str) -> bool:
    s = status.lower()
    return s.startswith("up")


def _service_entry(containers: list[dict[str, str]], service: str) -> dict[str, str] | None:
    for c in containers:
        if c["service"] == service:
            return c
    return None


def _service_up(containers: list[dict[str, str]], service: str) -> bool:
    c = _service_entry(containers, service)
    return bool(c and _is_running(c["status"]))


def _http_get(url: str, timeout: float = 5.0) -> tuple[bool, str | None]:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            code = int(getattr(resp, "status", None) or resp.getcode())
            if code < 500:
                return True, None
            return False, f"http_{code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, type(exc).__name__


def _http_via_docker_exec(ctx: AppContext, container_name: str) -> tuple[bool, str | None]:
    r = run_cmd(
        ctx,
        [
            "docker", "exec", container_name, "python", "-c",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=5)",
        ],
        timeout=20,
    )
    return (True, None) if r.ok else (False, "docker_exec_http_failed")


def run_check(ctx: AppContext) -> dict[str, Any]:
    print_status("INFO", f"check_ctfd revision={CHECK_CTFD_REVISION}")
    if not which("docker"):
        return {
            "status": "docker_absent",
            "passed": False,
            "revision": CHECK_CTFD_REVISION,
            "message": "Docker absent",
        }

    project = (ctx.env.get("COMPOSE_PROJECT_NAME") or "course-ctfd").strip()
    containers = _list_project_containers(ctx, project)

    compose_ps_ok = False
    compose_file = ctx.root / "compose" / "docker-compose.ctfd.yml"
    if compose_file.is_file():
        ps = run_cmd(
            ctx,
            ["docker", "compose", "-p", project, "-f", str(compose_file), "ps", "--format", "json"],
            cwd=ctx.root / "compose",
            env=_compose_runtime_env(ctx),
        )
        compose_ps_ok = ps.ok

    statuses = {c["service"] or c["name"]: c["status"] for c in containers}
    findings: dict[str, Any] = {
        "revision": CHECK_CTFD_REVISION,
        "project": project,
        "compose_ps_ok": compose_ps_ok,
        "statuses": statuses,
        "container_names": [c["name"] for c in containers],
        "services_up": {s: _service_up(containers, s) for s in ("db", "cache", "ctfd", "nginx")},
    }

    if not containers:
        return {
            "status": "compose_not_running",
            "passed": False,
            "revision": CHECK_CTFD_REVISION,
            "message": f"Aucun conteneur (project={project}). Sync checks/ + rm -rf checks/__pycache__",
            "findings": findings,
        }

    required = ("db", "cache", "ctfd")
    missing = [s for s in required if not _service_up(containers, s)]
    if missing:
        detail = []
        for s in missing:
            entry = _service_entry(containers, s)
            detail.append(f"{s}={entry['status'] if entry else 'absent'}")
        hint = ""
        ctfd = _service_entry(containers, "ctfd")
        if ctfd and ("restarting" in ctfd["status"].lower() or "exit" in ctfd["status"].lower()):
            hint = (
                " | Diagnostiquer: docker logs course-ctfd-ctfd-1 --tail 100 ; "
                "puis recreate sans montage plugins si besoin"
            )
        return {
            "status": "services_missing",
            "passed": False,
            "revision": CHECK_CTFD_REVISION,
            "message": f"Services non UP : {', '.join(detail)}{hint}",
            "findings": findings,
        }

    nginx_up = _service_up(containers, "nginx")
    ctfd_name = next(
        (c["name"] for c in containers if c["service"] == "ctfd" and _is_running(c["status"])),
        None,
    )

    http_ok = False
    http_path = None
    last_error = None
    for url in ("http://127.0.0.1/healthz", "http://127.0.0.1/"):
        ok, err = _http_get(url)
        if ok:
            http_ok, http_path = True, url
            break
        last_error = err

    if not http_ok and ctfd_name:
        ok, err = _http_via_docker_exec(ctx, ctfd_name)
        if ok:
            http_ok, http_path = True, f"docker-exec://{ctfd_name}:8000/"
        else:
            last_error = err

    findings["http_path"] = http_path
    findings["nginx_up"] = nginx_up

    if not http_ok:
        msg = f"HTTP non sain (dernier={last_error})"
        if not nginx_up:
            msg += " — nginx pas UP (souvent CTFd pas encore healthy)"
        return {
            "status": "http_unhealthy",
            "passed": False,
            "revision": CHECK_CTFD_REVISION,
            "message": msg,
            "findings": findings,
            "host_linux": is_linux(),
        }

    if not nginx_up:
        return {
            "status": "ctfd_healthy_nginx_missing",
            "passed": False,
            "revision": CHECK_CTFD_REVISION,
            "message": "CTFd OK en interne mais nginx absent",
            "findings": findings,
        }

    return {
        "status": "http_healthy",
        "passed": True,
        "revision": CHECK_CTFD_REVISION,
        "message": f"Sante HTTP OK via {http_path}",
        "findings": findings,
    }