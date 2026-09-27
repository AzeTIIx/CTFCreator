# Box `__BOX_NAME__` (template)

Squelette de box généré par `labctl new __BOX_NAME__`. À compléter.

## Structure
```
__BOX_NAME__/
├── box.yml                 # manifeste (nom, service d'entrée, ports, flags)
├── compose.yml             # services, paramétré par labctl (ENTRY_IP, ...)
└── challenge/
    └── target/Dockerfile   # la cible (sshd + flags + élévation d'exemple)
```

## À faire
1. **box.yml** : titre, description, `entry_service`, `ports`, `flags`.
2. **compose.yml** : ajoute tes services. Le service d'entrée reçoit `ENTRY_IP`
   sur le réseau `access` (routé). Les compagnons vont sur `internal` (non
   routé) pour un pivot.
3. **challenge/** : construis ta cible (foothold, énumération, privesc, pivot).
   Ne publie **aucun** port hôte : labctl route le VPN vers `ENTRY_IP`.
4. Flags cuits au build via `ARG FLAG_*` (valeurs par l'enseignant à l'`export`).

## Tester en local (Docker Desktop)
```bash
python -m labctl deploy __BOX_NAME__ -n 1
```
Puis, depuis un conteneur attaquant sur le même bridge, ou sur la Debian via WireGuard.

## Règles
Aucun secret réel ; flags `FLAG{...}` ; périmètre étudiant repris dans la
description CTFd. Voir `<client>/boxes/README.md`.
