# CTFCreator

Outillage commun pour monter un CTF sur CTFd, quel que soit le client (Fac CORTE, AFFLOKAT, …) :
plateforme durcie, publication des images de challenges, création des challenges dans CTFd,
format de challenge unique et modèles.

Les **challenges restent dans le dossier de chaque client** ; CTFCreator s'utilise en pointant
dessus. Un challenge qui respecte `standards/CHALLENGE-SPEC.md` se publie en trois commandes.

```text
CTFCreator/
├── ctfcreator/        shell interactif + CLI : validate, images, ctfd, publish, new, dockerignore
│   └── publisher/     build + push des images vers le registre (préflight sécurité)
├── platform/          VPS CTFd : hardening SSH, pare-feu, CTFd 3.8.6 + MariaDB + Redis + nginx,
│   │                  plugin challenge_containers (0xfbad, épinglé + correctifs), thème pixo
│   └── monitoring/    Prometheus + Grafana + cAdvisor + node_exporter (loopback, tunnel SSH)
├── labs/              box « machine » par binôme via WireGuard (labctl, lab-network)
├── templates/         web-container, tcp-container, static, box, ctfcreator.yml
├── standards/         CHALLENGE-SPEC.md, security-contract, composants (bot XSS durci)
└── tests/             101 tests (publisher, format, publication CTFd, shell, labctl)
```

## 1. Plateforme (une fois par VPS)

Voir `platform/README.md`. En résumé, en root sur le VPS (Debian 12 / Ubuntu 24.04) :

```bash
git clone … /opt/CTFCreator          # ou rsync depuis le poste
cd /opt/CTFCreator/platform
cp .env.example .env && chmod 600 .env          # CTFD_FQDN, ADMIN_SSH_USER, DOCKER_GID…
python3 scripts/main.py preflight
python3 scripts/main.py backup
python3 scripts/main.py harden-ssh --pubkey-file /home/<admin>/.ssh/id_ed25519.pub
python3 scripts/main.py configure-firewall
python3 scripts/main.py deploy
python3 scripts/main.py verify
bash monitoring/install.sh --ssh-tunnel "<admin> <admin2>"
```

Puis dans CTFd : **Admin → Config → Challenge Containers** (contexte Docker local) et
**Settings → Access Tokens** (jeton admin pour la publication).

## 2. Installer

```bash
cd /opt/CTFCreator
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                      # installe `ctfcreator` et `labctl` (mode éditable obligatoire)
```

## 3. Le shell `ctfcreator`

`ctfcreator` sans argument ouvre un shell à la GOAD : commandes tapées (`help`), prompt
`CTFCreator/<événement>/<version> ●` (● vert = jeton CTFd chargé), journal `[+]` `[*]` `[!]` `[-]`,
phases numérotées et chronométrées.

Un CTF = **un dossier d'événement**, dans le workspace (`/opt/ctf-events` s'il existe, sinon
`~/ctf-events`, ou `CTFCREATOR_EVENTS`) :

```text
<workspace>/<événement>/
├── event.yml        nom, client, dates, registre, version, URL CTFd, flags statiques, état par défaut
├── challenges/      un dossier par challenge (web, tcp, statique)
├── boxes/           un dossier par box labctl (box.yml + compose.yml + challenge.yml des jalons)
└── .ctfcreator/     généré : manifeste des images publiées
```

| Groupe | Commandes |
|---|---|
| Événement | `events`, `create` (assistant + import de challenges/box existants), `load <slug>`, `config`, `set <clé> <valeur>`, `status` |
| Contenu | `templates`, `new <web\|tcp\|static\|box> <slug>`, `derive <existant> <nouveau>`, `list [--ctfd]`, `check [slug…]` |
| Déploiement | `build [slug…]`, `publish [slug…] [--prune]`, `deploy` (pipeline complet), `open` / `hide [slug…]` |
| Box | `box <commande labctl>` (`use`, `deploy <n>`, `list`, `wg <user>\|all`, `endpoint <ip>`, `destroy`…), `labs` (shell labctl) |
| Session | `token` (jeton CTFd masqué), `clear`, `exit` |

Parcours type :

```text
CTFCreator/-/- ○ > create                      # assistant : nom, client, version, URL CTFd, import
CTFCreator/ctf-corse/2026.1 ○ > new web login-bypass
CTFCreator/ctf-corse/2026.1 ○ > derive login-bypass login-bypass-hard
CTFCreator/ctf-corse/2026.1 ○ > new box pivot
CTFCreator/ctf-corse/2026.1 ○ > check
CTFCreator/ctf-corse/2026.1 ○ > token
CTFCreator/ctf-corse/2026.1 ● > deploy          # [1/4] contrôle → [2/4] images → [3/4] CTFd → [4/4] box
CTFCreator/ctf-corse/2026.1 ● > box wg all      # profils WireGuard des binômes
CTFCreator/ctf-corse/2026.1 ● > open            # jour J
```

**Box ↔ CTFd.** Dans `boxes/<box>/challenge.yml`, chaque jalon porte `build_arg: FLAG_USER` et son
`flag`. CTFCreator transmet cette valeur à labctl (ARG de build de la box) et la publie comme flag
CTFd du jalon : une seule source de vérité. L'état labctl (instances, clés WireGuard) reste dans
`labs/labctl/state/`, commun au VPS : un seul serveur `wg0`.

**Dériver.** `derive` copie un challenge ou une box, renomme, et remet **tous** les flags en
placeholder : un challenge dérivé ne peut pas être publié avec le flag de son modèle.

## 4. Mode non interactif (scripts, CI)

Les commandes acceptent un dossier d'événement ou un simple dossier de challenges
(+ `ctfcreator.yml`) :

```bash
ctfcreator validate /opt/ctf-events/ctf-corse
ctfcreator images   /opt/ctf-events/ctf-corse
ctfcreator ctfd     /opt/ctf-events/ctf-corse [--apply] [--state visible] [--prune]
ctfcreator publish  /opt/ctf-events/ctf-corse
```

Comportement de la publication CTFd : identité = `name` ; absent → création (`hidden` par défaut),
présent → mise à jour des seuls champs qui diffèrent ; relancer ne change rien si tout est à jour ;
image = manifeste du publisher sinon `registre/dossier:version`, présence vérifiée dans le registre ;
`--prune` supprime les flags/tags/hints/fichiers absents des yml ; aucun flag affiché en clair.

### Migrer l'événement Fac CORTE existant

```text
CTFCreator/-/- ○ > create
  Nom affiché : CorsicanCTF 2026 … Version : 2026.1
  Importer des challenges existants : /opt/infra/deploy_challenges/challenges
```

Les challenges sont **copiés** : l'ancien dossier et ce qui est publié restent intacts ; les noms
CTFd étant identiques, `publish` ne fera que constater « à jour ».

## Tests

```bash
pip install -e ".[dev]" && pytest -q -m "not integration"
```

## Provenance

| Dossier | Origine | Modifications |
|---|---|---|
| `platform/` | AFFLOKAT `course-ctfd-infra` | correctifs `deploy` (DOCKER_GID/HOST_SSH_DIR transmis à Compose), `check_isolation` (nom de projet), drop-in SSH `10-` + contrôle `sshd -T`, supervision |
| `ctfcreator/publisher/` | AFFLOKAT `infra/deploy_challenges` | `.dockerignore` respecté au préflight, `--allow-static-flags`, dossiers `_*` ignorés |
| `labs/` | AFFLOKAT `infra/labctl`, `infra/lab-network` | chemins via `LABCTL_BOXES` / `LABCTL_STATE` |
| `templates/web-container`, `standards/` | Fac CORTE `_standards` | squelette complété, flag statique assumé |
| `templates/box` | AFFLOKAT `infra/challenges/_template` | — |

Les dépôts d'origine sont conservés tels quels.
