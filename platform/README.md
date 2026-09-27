# Plateforme CTFd (CTFCreator/platform)

Infrastructure rejouable pour un VPS **dédié** à un cours d’introduction à la cybersécurité : durcissement SSH, pare-feu, CTFd versionné, registre privé optionnel, vérifications et mode dégradé sans plugin d’instances non conforme.

## Système cible

- **OS supporté : Debian 12 (bookworm)** — uniquement.
- Ubuntu 24.04 n’est pas la cible documentée de cette livraison (peut être évaluée plus tard).
- Ne jamais déployer CTFd sur un hôte qui héberge d’autres services importants.

## État honnête de cette livraison


| Élément                                            | Statut                                                   |
| -------------------------------------------------- | -------------------------------------------------------- |
| Dépôt scripts / Compose / docs                     | Livré                                                    |
| Prévol sur VPS Linux dédié                         | **Non exécuté** (environnement de développement Windows) |
| Durcissement SSH validé par nouvelle connexion     | **Non exécuté**                                          |
| Pare-feu sur cible                                 | **Non exécuté**                                          |
| CTFd démarré sur VPS                               | **Non déployé** (variables cibles manquantes)            |
| Plugin instances conteneurisées                    | **challenge_containers accepté** ([0xfbad](https://github.com/0xfbad/ctfd-challenge-container-plugin)) + socket Docker |
| TheOriginalOrangeJuice/Docker-CTFd-Plugin@1b86917… | **Refusé** (ne pas installer)                            |
| Sauvegarde / restauration sur cible                | Exercées en dry-run / structure locale uniquement        |
| Tests d’isolation d’instances                      | **Non exécutés** (pas d’instances en mode degraded)      |


Voir `reports/EXECUTION.md` pour le journal d’exécution réel.

## Périmètre étudiants (modèle de menace)

Les étudiants ne sont autorisés à tester **que** :

- leur instance de challenge attribuée (si un jour un plugin conforme est accepté) ;
- les fichiers remis dans le cadre du cours.

Sont **hors périmètre** : l’hôte CTFd, le registre, les plugins, le reverse proxy, la base, Redis, le réseau d’administration et les instances voisines.

## Modèle de menace (admin mobile)

SSH est joignable depuis **n’importe quelle IP** (déplacements fréquents). La compensation obligatoire est le durcissement SSH : clés uniquement, pas de root login, pas de mot de passe. Le registre, la DB et Redis restent non publics.

## Architecture

```text
Internet autorisé
        |
   reverse proxy TLS (nginx, ports 80/443)
        |
      CTFd (image épinglée)
      /   \
  MariaDB  Redis
   (réseaux Docker internes — jamais publiés)

Mode degraded (livraison actuelle) :
  challenges statiques dans CTFd
  démonstrations conteneur : lancement séparé, contrôlé, local (hors plugin)

Worker challenges / plugin :
  BLOQUÉ tant qu’aucun plugin n’est accepté après audit
```

Détails : `docs/architecture.md`.

## Ports


| Port                   | Source                     | Service                            |
| ---------------------- | -------------------------- | ---------------------------------- |
| `SSH_PORT` (défaut 22) | **any** (admin mobile)     | SSH — mitigation : clés uniquement |
| 80/tcp                 | public si `HTTP_PUBLIC`    | redirect / ACME / HTTP             |
| 443/tcp                | public si `HTTPS_PUBLIC`   | HTTPS CTFd                         |
| 5000/tcp               | **jamais public**          | registre (`127.0.0.1`)             |
| 3306, 6379             | **jamais publiés**         | DB / Redis                         |
| ports challenges       | via plugin+proxy seulement | **inactifs** en degraded           |




## Versions épinglées


| Composant            | Référence                                                               |
| -------------------- | ----------------------------------------------------------------------- |
| CTFd                 | `ctfd/ctfd:3.8.6` (jamais `latest`)                                     |
| MariaDB              | `mariadb:10.11.13`                                                      |
| Redis                | `redis:7.2.16-bookworm` (remontée volontaire vs `redis:4` upstream EOL) |
| nginx                | `nginx:1.28.3`                                                          |
| alpine (permissions) | `alpine:3.21.3`                                                         |
| registry             | `registry:2.8.3`                                                        |
| Thème pixo           | commit `67abc2b8…` ([hmrserver/CTFd-theme-pixo](https://github.com/hmrserver/CTFd-theme-pixo)) |
| Plugin challenge_containers | commit `1023885a…` ([0xfbad/ctfd-challenge-container-plugin](https://github.com/0xfbad/ctfd-challenge-container-plugin)) |


Interdit : `latest`, suivi automatique de `main`. Vérifier les digests sur la cible après `docker pull`.

## Thème Pixo

Monté : `themes/pixo` → `/opt/CTFd/CTFd/themes/pixo` (ro).

Après `deploy` : Admin Panel → Config → Themes → **pixo** → Update.  
Compatibilité amont déclarée 3.3.0 ; sur 3.8.6, `THEME_FALLBACK` (défaut true) complète les templates manquants. Si l’UI casse → thème `core`.

## Prérequis

- **Python 3.11+** (stdlib uniquement — voir `requirements.txt`)
- Accès root/sudo sur un VPS Debian 12 **dédié**
- Fichier `.env` renseigné (copie de `.env.example`)
- Docker Engine + plugin Compose v2 installés **si** vous demandez le déploiement (pas d’install silencieuse)
- Compte SSH, FQDN CTFd, fournisseur VPS
- **Pas de filtre IP admin** : SSH ouvert depuis any ; compensé par `harden-ssh` (pas de mot de passe)

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate
python -m pip install -r requirements.txt
```



## Variables obligatoires (déploiement)

`VPS_PROVIDER`, `TARGET_HOST`, `ADMIN_SSH_USER`, `CTFD_FQDN`, `SSH_PORT`, `TARGET_DISTRO`, `TARGET_DISTRO_VERSION`

Sans `.env` réel (hors valeurs d’exemple), le déploiement s’arrête avec la liste des manques.

## Installation initiale (sur le VPS)

```bash
# 1. Copier le dépôt sur le VPS Debian 12
sudo mkdir -p /opt/CTFCreator/platform && sudo chown "$USER":"$USER" /opt/CTFCreator/platform
cd /opt/CTFCreator/platform
# synchroniser ce dépôt

# 2. Configurer
cp .env.example .env
chmod 600 .env
# éditer .env : provider, host, user, CTFD_FQDN, etc.
# DEPLOY_MODE=degraded
# PLUGIN_SELECTION=none

# 3. Prévol (lecture seule)
python3 scripts/main.py preflight

# 4. Sauvegarde avant modification
python3 scripts/main.py backup

# 5. Durcissement SSH (session SSH active + console fournisseur)
#    Obligatoire : passer la clé publique du compte ADMIN_SSH_USER
python3 scripts/main.py harden-ssh --pubkey-file /home/<admin>/.ssh/id_ed25519.pub
#    Depuis un poste qui a la clé privée (test auto optionnel) :
# python3 scripts/main.py harden-ssh --pubkey-file ./id_ed25519.pub --identity ./id_ed25519

# 6. Pare-feu
python3 scripts/main.py configure-firewall

# 7. Déploiement CTFd degraded
python3 scripts/main.py deploy

# 8. Vérifications
python3 scripts/main.py verify
```

Options globales : `--dry-run`, `--yes` (uniquement actions destructives documentées, ex. restauration nftables).

## Déploiement rejouable

`deploy` est idempotent : `compose up -d` sans suppression de volumes, secrets générés **une seule fois**, plugins refusés bloqués. Relancer `deploy` ne régénère pas les secrets existants.

## Sauvegardes / restauration

- `python3 scripts/main.py backup` : configs, archives de volumes nommés, dump SQL si DB joignable.
- Secrets locaux archivés hors bundle transportable.
- Restauration : voir `docs/operations.md`.
- Rollback : `python3 scripts/main.py rollback --target ssh|firewall|ctfd|all`



## Rotation des secrets

1. `backup`
2. Générer hors bande de nouveaux secrets

- Mettre à jour `.env` et `config/ctfd.env` (permissions 0600)

1. Recréer les services concernés (`docker compose up -d` — pas de prune)
2. Invalider sessions / tokens admin CTFd
3. `verify`



## Mise à jour épinglée

1. Choisir une version CTFd publiée (tag GitHub Release)
2. Mettre à jour `CTFD_IMAGE` et dépendances dans `.env`
3. Mettre à jour `docs/plugin-compatibility.md` si plugins
4. `backup` → `deploy` → `verify`
5. Ne jamais basculer sur `latest`



## Mode dégradé (livraison actuelle)

- CTFd pour challenges **statiques**
- Démonstrations Docker : lancement **séparé**, contrôlé, local, par l’enseignant
- Aucune instance étudiant via plugin
- Voir `docs/plugin-compatibility.md`



## Incident / retour arrière

Voir `docs/incident-response.md` et `python3 scripts/main.py rollback`.

## Limites

- Pas de plugin instances conforme promu
- TLS : HTTP prêt ; HTTPS à activer quand certificats fournis
- Redis 7.2 documenté (écart vs Compose upstream CTFd `redis:4`)
- Scripts conçus pour Linux ; prévol partiel hors Linux



## Tests locaux (dev)

```bash
python3 -m py_compile scripts/*.py checks/*.py tests/*.py
python3 -m unittest discover -s tests -v
python3 scripts/main.py preflight
python3 scripts/main.py deploy   # doit s'arrêter si .env cible manquant
```



## Licence des contenus de cours

Données étudiantes, comptes et challenges de ce dépôt sont **fictifs**. Aucun flag réel de production dans le code, les images, les configs ou les journaux.