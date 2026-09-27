# Architecture

## Objectif

Héberger CTFd et, le cas échéant, des instances de challenges **isolées**, sur un VPS Linux dédié. Aucun autre service métier sur le même hôte.

## Composants

| Rôle | Implémentation | Réseau Docker |
|------|----------------|---------------|
| Reverse proxy TLS | `nginx:1.28.3` | `ctfd_frontend` |
| Application | `ctfd/ctfd:3.8.6` | `ctfd_frontend`, `ctfd_app`, `ctfd_db`, `ctfd_cache` |
| Base | `mariadb:10.11.13` | `ctfd_db` (internal) |
| Cache | `redis:7.2.16-bookworm` | `ctfd_cache` (internal) |
| Registre privé | `registry:2.8.3` | `registry_private`, bind `127.0.0.1:5000` |
| Worker challenges | **non déployé** | — |

## Séparation des rôles

Comptes / réseaux logiques : `ctfd_frontend`, `ctfd_app`, `ctfd_db`, `ctfd_cache`, `challenge_worker` (réservé), `registry_private`.

## Règles d’isolement

- Socket Docker **jamais** monté dans CTFd ni dans un conteneur étudiant
- Pas de montage de `/`, `/etc`, `/var/run`, home, sockets
- DB / Redis : réseaux `internal: true`, aucun port publié
- Registre : jamais public
- Challenges : egress bloqué par défaut **quand** un plugin conforme existera ; aujourd’hui mode degraded

## Flux

```text
Client HTTPS → nginx:443 → ctfd:8000 → (db|cache)
```

## Volumes nommés

- `course_ctfd_mysql`
- `course_ctfd_redis`
- `course_ctfd_uploads`
- `course_ctfd_logs`
- `course_registry_data`

## Mode degraded

Sans plugin accepté, l’architecture s’arrête à CTFd statique. Les démonstrations conteneur sont hors bande (enseignant, machine contrôlée).

## Accès admin

Pas de filtre IP (`ADMIN_CIDR` retiré). SSH est joignable depuis any ; le durcissement par clés est obligatoire.
