"""Déploiement CTFd idempotent — mode degraded par défaut si plugin non conforme."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    AppContext,
    build_context,
    confirm,
    generate_secret,
    is_linux,
    print_status,
    redact_text,
    require_for_deploy,
    run_cmd,
    utc_now,
    validate_image_ref,
    which,
    write_report,
)
from preflight import run_preflight  # noqa: E402

REFUSED_PLUGINS = {
    "TheOriginalOrangeJuice/Docker-CTFd-Plugin",
    "theoriginalorangejuice/docker-ctfd-plugin",
}


def _ensure_secrets(ctx: AppContext) -> dict[str, str]:
    """Génère les secrets une seule fois ; ne remplace jamais silencieusement."""
    env_path = ctx.root / ".env"
    ctfd_env = ctx.root / "config" / "ctfd.env"
    created: dict[str, str] = {}

    existing = {}
    if env_path.is_file():
        from common import load_env_file

        existing.update(load_env_file(env_path))

    needed = ["SECRET_KEY", "DB_ROOT_PASSWORD", "DB_PASSWORD", "REDIS_PASSWORD"]
    for key in needed:
        if existing.get(key) or ctx.env.get(key):
            continue
        if not confirm(ctx, f"Générer un secret pour {key} (écriture locale uniquement) ?"):
            raise RuntimeError(f"Secret manquant : {key}")
        value = generate_secret(32)
        created[key] = value
        ctx.env[key] = value

    if created and not ctx.dry_run:
        # Append au .env sans réécrire les secrets existants
        lines = []
        if env_path.is_file():
            lines = env_path.read_text(encoding="utf-8").splitlines()
        else:
            example = ctx.root / ".env.example"
            if example.is_file():
                lines = example.read_text(encoding="utf-8").splitlines()
        for key, value in created.items():
            # Retirer lignes vides placeholder
            lines = [ln for ln in lines if not ln.startswith(f"{key}=") and not ln.startswith(f"#{key}=")]
            lines.append(f"{key}={value}")
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            pass
        print_status("OK", f"Secrets générés et stockés dans .env ({len(created)} clés) — non affichés")

    # Écrire config/ctfd.env sans secrets dans stdout
    if not ctfd_env.is_file() and not ctx.dry_run:
        secret_key = ctx.env.get("SECRET_KEY") or existing.get("SECRET_KEY") or created.get("SECRET_KEY")
        db_password = ctx.env.get("DB_PASSWORD") or existing.get("DB_PASSWORD") or created.get("DB_PASSWORD")
        redis_password = (
            ctx.env.get("REDIS_PASSWORD") or existing.get("REDIS_PASSWORD") or created.get("REDIS_PASSWORD")
        )
        if secret_key and db_password and redis_password:
            content = (
                f"SECRET_KEY={secret_key}\n"
                f"DATABASE_URL=mysql+pymysql://ctfd:{db_password}@db:3306/ctfd\n"
                f"REDIS_URL=redis://:{redis_password}@cache:6379\n"
                "UPLOAD_FOLDER=/var/uploads\n"
                f"WORKERS={ctx.env.get('CTFD_WORKERS', '2')}\n"
                "LOG_FOLDER=/var/log/CTFd\n"
                "ACCESS_LOG=-\n"
                "ERROR_LOG=-\n"
                "REVERSE_PROXY=true\n"
            )
            ctfd_env.write_text(content, encoding="utf-8")
            try:
                os.chmod(ctfd_env, 0o600)
            except OSError:
                pass
            print_status("OK", "config/ctfd.env créé (permissions restrictives)")
    return {k: "***" for k in created}


def _assert_no_refused_plugin(ctx: AppContext) -> None:
    selection = (ctx.env.get("PLUGIN_SELECTION") or "none").strip()
    if selection.lower() in {"none", "degraded", ""}:
        return
    for refused in REFUSED_PLUGINS:
        if refused.lower() in selection.lower():
            raise RuntimeError(
                "Plugin refusé par audit : TheOriginalOrangeJuice/Docker-CTFd-Plugin "
                "(commit 1b86917…). Déploiement étudiant conteneurisé bloqué. "
                "Voir docs/plugin-compatibility.md — mode degraded obligatoire."
            )
    plugins_dir = ctx.root / "plugins"
    if plugins_dir.is_dir():
        for path in plugins_dir.rglob("*"):
            text = path.name.lower()
            if "orangejuice" in text or "theoriginalorangejuice" in text:
                raise RuntimeError(
                    f"Artefact de plugin refusé détecté : {path.relative_to(ctx.root)}"
                )


def _compose_env(ctx: AppContext) -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "CTFD_IMAGE",
        "MARIADB_IMAGE",
        "REDIS_IMAGE",
        "NGINX_IMAGE",
        "ALPINE_IMAGE",
        "REGISTRY_IMAGE",
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
        "DOCKER_GID",
        "HOST_SSH_DIR",
        "CTFD_COURSE_IMAGE",
    ):
        if ctx.env.get(key):
            env[key] = ctx.env[key]
    return env


def run_deploy(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    print_status("INFO", "Déploiement CTFd — vérifications préalables")

    # Toujours prévol d'abord
    pre_code = run_preflight(ctx)
    if pre_code not in (0,):
        print_status("FAIL", "Prévol en échec — déploiement annulé")
        return pre_code

    missing = require_for_deploy(ctx.env)
    if missing:
        print_status(
            "FAIL",
            "Déploiement arrêté — variables obligatoires manquantes : " + ", ".join(missing),
        )
        write_report(
            ctx,
            "deploy-blocked",
            {"generated_at": utc_now(), "missing": missing, "reason": "config_incomplete"},
        )
        return 2

    if not is_linux():
        print_status(
            "FAIL",
            "Déploiement CTFd refusé : l'hôte courant n'est pas Linux. "
            "Exécuter ce script sur le VPS Debian 12 dédié.",
        )
        write_report(
            ctx,
            "deploy-blocked",
            {"generated_at": utc_now(), "reason": "not_linux", "platform": sys.platform},
        )
        return 2

    try:
        _assert_no_refused_plugin(ctx)
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 3

    mode = (ctx.env.get("DEPLOY_MODE") or "degraded").strip().lower()
    selection = (ctx.env.get("PLUGIN_SELECTION") or "none").strip().lower()

    if mode == "containers":
        if selection != "challenge_containers":
            print_status(
                "FAIL",
                "DEPLOY_MODE=containers exige PLUGIN_SELECTION=challenge_containers "
                "(plugin 0xfbad accepté documenté).",
            )
            return 3
        compat = (ctx.root / "docs" / "plugin-compatibility.md").read_text(encoding="utf-8")
        chunk_ok = False
        idx = compat.find("0xfbad/ctfd-challenge-container-plugin")
        if idx >= 0:
            piece = compat[idx : idx + 2000]
            for line in piece.splitlines():
                if "Décision" in line and "accepté" in line.lower() and "refusé" not in line.lower():
                    chunk_ok = True
                    break
        if not chunk_ok:
            print_status("FAIL", "challenge_containers non marqué accepté dans la doc")
            return 3
        if not (ctx.root / "plugins" / "challenge_containers" / "__init__.py").is_file():
            print_status("FAIL", "Plugin challenge_containers manquant sur disque")
            return 3
    elif mode != "degraded":
        print_status("FAIL", f"DEPLOY_MODE inconnu : {mode}")
        return 2

    # Valider images
    for key in ("CTFD_IMAGE", "MARIADB_IMAGE", "REDIS_IMAGE", "NGINX_IMAGE", "ALPINE_IMAGE"):
        ref = ctx.env.get(key, "")
        if key == "CTFD_IMAGE" and not ref:
            continue
        if ref and not validate_image_ref(ref):
            print_status("FAIL", f"Image non épinglée / invalide : {key}")
            return 2
    # Image build locale course-ctfd:… autorisée
    course_img = ctx.env.get("CTFD_COURSE_IMAGE", "course-ctfd:3.8.6-containers")
    if "latest" in course_img.split(":")[-1]:
        print_status("FAIL", "CTFD_COURSE_IMAGE ne doit pas utiliser latest")
        return 2

    if not which("docker"):
        if (ctx.env.get("INSTALL_DOCKER_IF_MISSING") or "").lower() in {"1", "true", "yes"}:
            print_status(
                "FAIL",
                "INSTALL_DOCKER_IF_MISSING=true mais l'installation automatique Docker "
                "n'est pas intégrée pour éviter les dérives ; installer Docker manuellement "
                "puis relancer.",
            )
        else:
            print_status("FAIL", "Docker absent — installation non demandée explicitement")
        return 2

    confirm_msg = (
        "Déployer CTFd en mode containers (plugin challenge_containers / 0xfbad + socket Docker) ?"
        if mode == "containers"
        else "Déployer CTFd en mode degraded (challenges statiques) ?"
    )
    if not confirm(ctx, confirm_msg):
        return 1

    try:
        secrets_meta = _ensure_secrets(ctx)
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 2

    compose_file = ctx.root / "compose" / "docker-compose.ctfd.yml"
    if not compose_file.is_file():
        print_status("FAIL", f"Fichier Compose manquant : {compose_file}")
        return 2

    env = _compose_env(ctx)
    project = ctx.env.get("COMPOSE_PROJECT_NAME", "course-ctfd")

    # Build image CTFd + deps plugin challenge_containers puis pull des autres
    build = run_cmd(
        ctx,
        ["docker", "compose", "-p", project, "-f", str(compose_file), "build", "ctfd"],
        cwd=ctx.root / "compose",
        env=env,
        timeout=1800,
    )
    if not build.ok and not ctx.dry_run:
        print_status("FAIL", "Échec du build de l'image CTFd cours")
        print(redact_text(build.stderr))
        return 4

    pull = run_cmd(
        ctx,
        ["docker", "compose", "-p", project, "-f", str(compose_file), "pull", "--ignore-buildable"],
        cwd=ctx.root / "compose",
        env=env,
        timeout=1800,
    )
    if not pull.ok and not ctx.dry_run:
        # pull --ignore-buildable peut ne pas exister sur anciennes versions
        pull = run_cmd(
            ctx,
            ["docker", "compose", "-p", project, "-f", str(compose_file), "pull"],
            cwd=ctx.root / "compose",
            env=env,
            timeout=1800,
        )
    if not pull.ok and not ctx.dry_run:
        print_status("WARN", "Pull partiel — poursuite si les images locales suffisent")

    up = run_cmd(
        ctx,
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(compose_file),
            "up",
            "-d",
            "--remove-orphans=false",
        ],
        cwd=ctx.root / "compose",
        env=env,
        timeout=1800,
    )
    if not up.ok and not ctx.dry_run:
        print_status("FAIL", "Échec docker compose up")
        print(redact_text(up.stderr))
        return 4

    # Registre optionnel
    registry_enabled = (ctx.env.get("REGISTRY_ENABLED") or "").lower() in {"1", "true", "yes"}
    if registry_enabled:
        reg_file = ctx.root / "compose" / "docker-compose.registry.yml"
        existing = run_cmd(
            ctx,
            ["docker", "ps", "-a", "--filter", "name=registry", "--format", "{{.Names}}"],
        )
        if existing.ok and existing.stdout.strip():
            print_status(
                "WARN",
                "Un conteneur registry existe déjà — réutilisation, pas de réinitialisation.",
            )
        else:
            run_cmd(
                ctx,
                [
                    "docker",
                    "compose",
                    "-p",
                    "course-registry",
                    "-f",
                    str(reg_file),
                    "up",
                    "-d",
                ],
                cwd=ctx.root / "compose",
                env=env,
            )

    write_report(
        ctx,
        "deploy",
        {
            "generated_at": utc_now(),
            "mode": mode,
            "project": project,
            "secrets_created_keys": list(secrets_meta.keys()),
            "plugins": selection,
            "docker_api": "unix:///var/run/docker.sock (monté dans CTFd — exigence 0xfbad)",
            "note": (
                "Après démarrage : Admin → Config → Challenge Containers ; "
                "Themes → pixo ; précharger les images challenges sur le daemon."
            ),
        },
    )
    print_status(
        "OK",
        f"Déploiement {mode} terminé. "
        "Configurer Challenge Containers dans /admin/config ; "
        "vérifier DOCKER_GID et le socket. Dashboard : /containers/dashboard.",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_deploy())
