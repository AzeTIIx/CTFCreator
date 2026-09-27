# Compatibilité des plugins CTFd (instances conteneurisées)

Document d’audit. **Aucune compatibilité n’est inventée.**  
Date de rédaction / mise à jour : 2026-09-14.  
CTFd cible documenté : **3.8.6**.

Légende des décisions :

- **accepté** — retenu par l’opérateur cours pour ce dépôt (risques résiduels documentés)
- **accepté sous conditions** — pistes intéressantes, gaps restants, **non promu**
- **refusé** — ne pas installer / ne pas présenter comme prêt

---

## 1. TheOriginalOrangeJuice/Docker-CTFd-Plugin

| Champ | Valeur |
|-------|--------|
| Dépôt / URL | https://github.com/TheOriginalOrangeJuice/Docker-CTFd-Plugin |
| Version / commit épinglé | `1b86917d44fab583d2cee00b0875e8442b6827c9` |
| **Décision** | **refusé** |

Motifs inchangés : exposition Compose/secrets, contrôles CTFd, isolation, injection de flag.

---

## 2. 0xfbad/ctfd-challenge-container-plugin (`challenge_containers`)

| Champ | Valeur |
|-------|--------|
| Dépôt / URL | https://github.com/0xfbad/ctfd-challenge-container-plugin |
| Version / commit épinglé | `1023885a0bbcdcd0c027c132c309ac690233ecd2` |
| Licence | **Non déclarée** sur GitHub au moment de l’épinglage — risque juridique résiduel **accepté par l’opérateur** |
| Version CTFd visée | Non matrice officielle 3.8.6 ; tests d’intégration à faire sur la cible |
| Type de challenge | `container` |
| Fonctionnalités | Instances per-user/team, expiration/renew, multi-hôte (contexts), freshness tokens, stacks Compose |
| Permissions | **Socket Docker** (contexte local `unix:///var/run/docker.sock`) ; contexts SSH optionnels |
| Durcissement revendiqué amont | `cap_drop=ALL`, `no-new-privileges`, `pids_limit=256`, `auto_remove` |
| **Décision** | **accepté** (choix opérateur 2026-09-14) |

### Activation retenue

- Montage : `plugins/challenge_containers` → `/opt/CTFd/CTFd/plugins/challenge_containers`
- Accès Docker : **socket hôte** + `group_add: DOCKER_GID` (obligatoire)
- Volumes amont : `~/.docker` (volume nommé), `~/.ssh` (copie depuis `HOST_SSH_DIR`)
- `HOME=/home/ctfd` pour la résolution des contexts
- Pare-feu : ouvrir **40000–59999/tcp** (ports dynamiques du plugin)
- Image CTFd cours : `course-ctfd:3.8.6-containers`
- Config : `/admin/config` → Challenge Containers ; dashboard `/containers/dashboard`
- Images challenges **préchargées** avant Lancer

### Écarts fréquents qui empêchent de lancer un challenge

1. `DOCKER_GID` faux → `docker.ping()` échoue au boot → **aucun contexte `local` seedé** (échec silencieux)
2. Image absente du daemon → Lancer refuse
3. Pare-feu sans 40000–59999 → instance créée mais injoignable
4. Type de challenge ≠ `container` (ancien type `docker` offsecginger)
5. Plugin non chargé (deps manquantes / logs CTFd)

### Hostname de connexion (NDD vs IP)

Par défaut amont, le contexte `local` renvoyait le **Host de la requête CTFd**
(donc le NDD) — inutilisable si le reverse proxy / DNS n’expose pas les ports
dynamiques `40000–59999`.

**Patch cours** dans `plugins/challenge_containers/src/views/helpers.py` :
`pub_hostname` du contexte est honoré aussi pour `local`.

Configurer l’IP publique du VPS comme `pub_hostname` du contexte `local`
(Admin → Config → Challenge Containers → Edit, ou SQL).

À chaque (re)création de challenge, le champ **Image** doit être exact
(`localhost:5000/<slug>:<version>`, sans espace / CRLF / guillemets).
Un patch sanitize `image.strip()` dans `container_manager.py` avant `containers.run`.

### Format challenge.yml (extrait)

```yaml
type: container
value: 0
image: aster-c00-prise-en-main:2026.1
port: 8080
ctype: web
```

---

## 3. offsecginger/CTFd-Docker-Challenges (`docker_challenges`)

| Champ | Valeur |
|-------|--------|
| Dépôt / URL | https://github.com/offsecginger/CTFd-Docker-Challenges |
| Commit précédemment vendored | `47c068ca6654b85701f69d06cd2c025a71ba2314` |
| **Décision** | **remplacé** — archivé sous `plugins/_archived_docker_challenges_offsecginger` si présent ; **ne plus monter** |

---

## 4. Autres forks type namhikelo / a-tt-om

| **Décision** | **refusé** pour production cours (état actuel) |

---

## Synthèse

| Plugin | Décision | Action dépôt |
|--------|----------|--------------|
| TheOriginalOrangeJuice@1b86917… | **refusé** | Bloqué |
| **0xfbad@1023885a…** | **accepté** | Monté + socket Docker |
| offsecginger@47c068ca… | remplacé | Archivé / non monté |

**Conséquence :** `DEPLOY_MODE=containers`, `PLUGIN_SELECTION=challenge_containers` ; thème **pixo** monté.

---

## Critères de recette (rappel)

Un plugin d’instances n’est « prêt séance » que si la checklist d’isolation a été exécutée sur la cible (2 instances, pas d’accès hôte/registre/DB non prévus, limites, nettoyage). Voir `docs/verification-checklist.md`.
