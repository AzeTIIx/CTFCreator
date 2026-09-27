"""Utilitaires communs : configuration, exécution sécurisée, journalisation sans secrets."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence

SECRET_KEY_NAMES = {
    "SECRET_KEY",
    "DB_ROOT_PASSWORD",
    "DB_PASSWORD",
    "REDIS_PASSWORD",
    "DATABASE_URL",
    "REDIS_URL",
    "PRESET_ADMIN_PASSWORD",
    "PRESET_ADMIN_TOKEN",
    "REGISTRY_PASSWORD",
    "PASSWORD",
    "TOKEN",
    "API_KEY",
}

SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+"
)

IMAGE_RE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?"
    r"(?:@sha256:[a-f0-9]{64})?$"
)

PORT_RE = re.compile(r"^\d{1,5}$")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass
class AppContext:
    root: Path
    env: MutableMapping[str, str] = field(default_factory=dict)
    dry_run: bool = False
    assume_yes: bool = False
    reports_dir: Path = field(default_factory=Path)

    def __post_init__(self) -> None:
        if not self.reports_dir or self.reports_dir == Path():
            self.reports_dir = self.root / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_text(text: str, extra_secrets: Sequence[str] | None = None) -> str:
    redacted = SECRET_VALUE_PATTERN.sub(r"\1=***REDACTED***", text)
    for name in SECRET_KEY_NAMES:
        redacted = re.sub(
            rf"(?i)({re.escape(name)}\s*[=:]\s*)(\S+)",
            r"\1***REDACTED***",
            redacted,
        )
    if extra_secrets:
        for secret in extra_secrets:
            if secret and len(secret) >= 4:
                redacted = redacted.replace(secret, "***REDACTED***")
    return redacted


def load_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        data[key] = value
    return data


def merge_env(root: Path) -> dict[str, str]:
    merged: dict[str, str] = {}
    merged.update(load_env_file(root / ".env.example"))
    merged.update(load_env_file(root / ".env"))
    # Variables d'environnement process priment
    for key, value in os.environ.items():
        if key in merged or key in SECRET_KEY_NAMES or key.startswith(
            (
                "TARGET_",
                "ADMIN_",
                "CTFD_",
                "SSH_",
                "TLS_",
                "DEPLOY_",
                "COMPOSE_",
                "INSTALL_",
                "BACKUP_",
                "DATA_",
                "REGISTRY_",
                "FIREWALL_",
                "HTTP_",
                "HTTPS_",
                "PLUGIN_",
                "ALLOW_",
                "SECOND_",
                "VPS_",
                "DRY_",
                "DB_",
                "REDIS_",
                "SECRET_",
                "MARIADB_",
                "NGINX_",
                "ALPINE_",
                "CHALLENGE_",
            )
        ):
            merged[key] = value
    return merged


def build_context(dry_run: bool = False, assume_yes: bool = False) -> AppContext:
    root = repo_root()
    env = merge_env(root)
    if env.get("DRY_RUN", "").lower() in {"1", "true", "yes"}:
        dry_run = True
    return AppContext(root=root, env=env, dry_run=dry_run, assume_yes=assume_yes)


def missing_required(env: Mapping[str, str], keys: Sequence[str]) -> list[str]:
    missing: list[str] = []
    for key in keys:
        value = (env.get(key) or "").strip()
        if not value or value.endswith(".example.invalid") or value == "replace-me":
            # Les FQDN d'exemple sont considérés manquants pour le déploiement réel
            if key in {
                "TARGET_HOST",
                "CTFD_FQDN",
                "ADMIN_SSH_USER",
                "VPS_PROVIDER",
            }:
                if (
                    not value
                    or "example.invalid" in value
                    or value in {"OVH", "replace-me"}
                    and key != "VPS_PROVIDER"
                ):
                    # VPS_PROVIDER=OVH dans l'exemple est fictif — exiger surcharge
                    if key == "VPS_PROVIDER" and value in {"", "OVH", "example"}:
                        # Accepter si l'opérateur a fourni une valeur non vide non-exemple
                        # Pour l'exemple .env.example, OVH est placeholder → manquant si .env absent
                        missing.append(key)
                        continue
            if not value or "example.invalid" in value or value.startswith("replace-me"):
                missing.append(key)
                continue
        if key == "VPS_PROVIDER" and value in {"OVH"} and not (repo_root() / ".env").is_file():
            missing.append(key)
    # Dédupliquer en préservant l'ordre
    seen: set[str] = set()
    out: list[str] = []
    for item in missing:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def require_for_deploy(env: Mapping[str, str]) -> list[str]:
    keys = [
        "VPS_PROVIDER",
        "TARGET_HOST",
        "ADMIN_SSH_USER",
        "CTFD_FQDN",
        "SSH_PORT",
        "TARGET_DISTRO",
        "TARGET_DISTRO_VERSION",
    ]
    missing: list[str] = []
    example_markers = ("example.invalid", "replace-me")
    has_dotenv = (repo_root() / ".env").is_file()
    if not has_dotenv:
        return list(keys)
    for key in keys:
        value = (env.get(key) or "").strip()
        if not value:
            missing.append(key)
            continue
        if any(marker in value for marker in example_markers):
            missing.append(key)
            continue
    return list(dict.fromkeys(missing))


def validate_image_ref(ref: str) -> bool:
    if not ref or not IMAGE_RE.match(ref):
        return False
    name_tag = ref.split("@", 1)[0]
    if ":" in name_tag:
        tag = name_tag.rsplit(":", 1)[-1]
        if tag == "latest":
            return False
    elif "@" not in ref:
        # Tag flottant implicite interdit
        return False
    return True


def validate_port(value: str) -> bool:
    if not PORT_RE.match(value):
        return False
    port = int(value)
    return 1 <= port <= 65535


def validate_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def confirm(ctx: AppContext, message: str) -> bool:
    if ctx.assume_yes:
        return True
    if ctx.dry_run:
        print(f"[dry-run] confirmation ignorée : {message}")
        return True
    try:
        answer = input(f"{message} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes", "o", "oui"}


def run_cmd(
    ctx: AppContext,
    argv: Sequence[str],
    *,
    check: bool = False,
    capture: bool = True,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | None = None,
) -> CommandResult:
    import subprocess

    if not argv:
        raise ValueError("argv vide")
    display = redact_text(" ".join(argv))
    if ctx.dry_run:
        print(f"[dry-run] exec: {display}")
        return CommandResult(list(argv), 0, "", "")

    print(f"[exec] {display}")
    completed = subprocess.run(
        list(argv),
        shell=False,
        capture_output=capture,
        text=True,
        cwd=str(cwd) if cwd else None,
        env=dict(os.environ, **(env or {})),
        timeout=timeout,
        check=False,
    )
    stdout = redact_text(completed.stdout or "")
    stderr = redact_text(completed.stderr or "")
    result = CommandResult(list(argv), completed.returncode, stdout, stderr)
    if check and not result.ok:
        raise RuntimeError(f"commande échouée ({result.returncode}): {display}")
    return result


def which(binary: str) -> str | None:
    return shutil.which(binary)


def generate_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def write_report(ctx: AppContext, name: str, content: Mapping[str, Any] | str) -> Path:
    import json

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = ctx.reports_dir / f"{name}-{stamp}.json"
    if isinstance(content, str):
        path = path.with_suffix(".txt")
        path.write_text(redact_text(content), encoding="utf-8")
    else:
        safe = json.loads(redact_text(json.dumps(content, default=str)))
        path.write_text(json.dumps(safe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Permissions restrictives si POSIX
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"[report] {path}")
    return path


def print_status(level: str, message: str) -> None:
    print(f"[{level}] {message}")


def fail(message: str, code: int = 1) -> int:
    print_status("FAIL", message)
    return code


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_windows() -> bool:
    return sys.platform.startswith("win")
