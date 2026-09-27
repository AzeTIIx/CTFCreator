# Format `challenge.yml` — CTFCreator v1

Un challenge = un dossier. Le **nom du dossier** est l'identifiant technique (image
`<registre>/<dossier normalisé>:<version>`) ; le champ `name` est l'identité côté CTFd
(un challenge CTFd est retrouvé par son `name` exact, qui doit donc être unique).

```text
<événement>/
├── event.yml                   # réglages (registre, version, URL CTFd…) — créé par `create`
├── .ctfcreator/publication/    # généré : manifeste des images publiées (ignoré par git)
├── boxes/<box>/                # box labctl (voir « Box » plus bas)
└── challenges/<slug>/          # (_* et .* ignorés)
    ├── challenge.yml           # CE format
    ├── Dockerfile              # challenge conteneur (USER non-root, pas de latest)
    ├── .dockerignore           # obligatoire (exclut .git, solve.md, tests, expected, *.md, challenge.yml)
    ├── src/                    # application
    ├── security-contract.yaml  # faiblesse unique déclarée, périmètre, durcissement
    ├── check_challenge.sh      # recette locale (build + run durci + tests)
    ├── tests/                  # exploit_poc.py (positif), security_audit.py (négatif)
    ├── README.md               # fiche enseignant
    └── solve.md                # solution (jamais dans l'image)
```

## Champs

| Champ | Obligatoire | Défaut | Rôle |
|---|---|---|---|
| `name` | oui | — | Titre CTFd, identité unique |
| `category` | oui | — | Catégorie CTFd |
| `description` | non | `""` | Markdown affiché aux participants |
| `connection_info` | non | `""` | ex. `http://{{host}}:{{port}}/` |
| `function` | non | `static` | `static`, `linear` ou `logarithmic` |
| `value` | si `static` | `0` | Points fixes |
| `initial` / `minimum` / `decay` | si dynamique | — | Score dynamique (CTFd ≥ 3.8) |
| `state` | non | `hidden` à la création | `visible` / `hidden` ; absent = inchangé lors d'une mise à jour |
| `max_attempts` | non | — | Tentatives max |
| `flags` | oui | — | chaînes (static, sensible à la casse) ou `{content, type: static\|regex, data: ""\|case_insensitive}` |
| `tags` | non | `[]` | chaînes |
| `hints` | non | `[]` | chaînes ou `{content, cost}` |
| `files` | non | `[]` | chemins relatifs au dossier, téléversés dans CTFd |
| `ctfd_plugin` | conteneur | — | voir ci-dessous ; absent = challenge `standard` |

### Bloc `ctfd_plugin` (plugin 0xfbad `challenge_containers`)

| Champ | Défaut | Rôle |
|---|---|---|
| `type` | `container` | seul type géré |
| `port` | — (obligatoire) | port interne exposé par l'image |
| `ctype` | `web` | `web`, `tcp`, `ssh` |
| `image` | résolue | **ne pas renseigner** : `manifeste publisher` > `registre/dossier:version` |
| `max_memory_mb`, `max_cpu` | — | limites (prévoir ≥ 384 Mo pour un bot Chromium) |
| `expiration_seconds`, `max_renewals` | plugin | durée de vie des instances |
| `command`, `cap_add`, `ssh_username`, `volumes`, `docker_context` | — | options avancées du plugin |
| `env` | — | **ignoré** : le plugin ne transmet aucune variable par challenge |

## Flags

- Flag **statique**, identique dans `challenge.yml` et dans l'image (`ENV FLAG=…` ou fichier
  généré au démarrage). Publication avec `allow_static_flags: true` (décision opérateur).
- Les placeholders (`CCTF{local_test_only}`, `AFLO{local_test_only}`, `flag{placeholder}`…) ne
  sont **jamais** publiés ; un challenge qui n'a que des placeholders est bloqué.
- Aucun outil CTFCreator n'affiche un flag en clair.

## Box (labctl)

`boxes/<box>/` contient `box.yml` + `compose.yml` (modèle : `new box <slug>`) et un
`challenge.yml` au format `aster-multi-milestone/1` : un challenge CTFd `standard` par jalon.
Un jalon peut porter `build_arg: FLAG_USER` : sa valeur `flag` est alors transmise par
CTFCreator à labctl comme ARG de build de la box **et** publiée comme flag CTFd du jalon.
Aucun port hôte publié dans `compose.yml` : l'accès passe par WireGuard.

## Formats historiques acceptés

- **Legacy AFFLOKAT** : `type: container`, `image`, `port`, `ctype` à la racine.
- **`schema: aster-multi-milestone/1`** : un challenge CTFd `standard` par entrée de
  `milestones` (`name`, `value`, `description`, `flag`, `tags`, `hints`) ; `scope_notice`
  est ajouté à chaque description.

## Règles de sécurité (préflight `ctfcreator validate`)

- `.dockerignore` présent et excluant `.git`, `solve.md`, `tests`, `expected`.
- Aucun `.env`, clé privée ou secret dans le **contexte de build** (le `.dockerignore` est respecté).
- `USER` non-root, pas de `latest`, pas de volume hôte, socket Docker, `privileged`, host network.
- Flags réels refusés dans le contexte de build sauf `allow_static_flags`.
- Après build : image inspectée (utilisateur, ports, historique, contenu) avant push.
