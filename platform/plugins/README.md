# Plugins CTFd

| Dossier | Statut |
|---------|--------|
| `challenge_containers` ([0xfbad](https://github.com/0xfbad/ctfd-challenge-container-plugin) @ `1023885a…`) | **Accepté** — monté dans Compose + socket Docker |
| `_archived_docker_challenges_offsecginger` | Archivé — ne pas monter |

## Activation

1. `PLUGIN_SELECTION=challenge_containers` et `DEPLOY_MODE=containers` dans `.env`
2. `DOCKER_GID` = GID du groupe `docker` hôte
3. Rebuild image CTFd : `docker compose build ctfd`
4. Admin → Config → **Challenge Containers** (contexts, images)
5. Dashboard : `/containers/dashboard`
6. Challenges : type **`container`**, image préchargée, `port` interne, `ctype: web` pour le web

## Sécurité

Le socket Docker est monté dans CTFd (exigence amont du contexte local). Risque résiduel documenté dans `docs/plugin-compatibility.md`.
