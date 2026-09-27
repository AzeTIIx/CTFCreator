# Opérations

## Ordre nominal

1. `preflight` (RO)
2. `backup`
3. `harden-ssh` (**obligatoire** : SSH est ouvert depuis any)
4. `configure-firewall`
5. `deploy`
6. `verify`

## Pare-feu — changement

1. `backup` + dump règles (`/var/backups/course-ctfd/firewall/`)
2. Modifier `.env` (`HTTP_PUBLIC`, `SSH_PORT`, …)
3. `configure-firewall`
4. Vérifier SSH par clé depuis un autre réseau ; password auth doit échouer

## Pare-feu — retour arrière

- **nftables** : `nft -f` sur le dump sauvegardé avec `rollback --target firewall --yes`
- **ufw** : restauration manuelle à partir de `ufw-status.txt` (ufw ne rejoue pas un export status)

## SSH — retour arrière

```bash
python3 scripts/main.py rollback --target ssh
# ou restauration manuelle depuis /var/backups/course-ctfd/sshd/<stamp>/
```

Console fournisseur si SSH inaccessible.

## Sauvegarde

```bash
python3 scripts/main.py backup
```

Contenu typique : configs Compose, tar.gz des volumes, `ctfd.sql.gz` si DB up. Secrets dans `secrets_local/` hors bundle.

## Restauration CTFd (manuel contrôlé)

1. `compose stop` (pas `down -v`)
2. Restaurer volumes depuis tar (conteneur alpine, montage volume)
3. Restaurer SQL si besoin (`docker exec -i … mysql`)
4. `compose up -d`
5. `verify`

## Rotation secrets

Voir README. Ne jamais logger les nouvelles valeurs.

## Mise à jour épinglée

Changer les tags dans `.env` → `backup` → `deploy` → `verify`. Documenter dans le rapport.

## Healthcheck

Le readiness CTFd repose sur une requête HTTP (compose healthcheck + `check_ctfd`), pas sur la seule présence du processus.

## Vérification externe

- SSH depuis n’importe quel réseau : OK **avec clé**
- SSH password : échec après harden-ssh
- HTTPS public : page CTFd
- `HOST:5000` depuis Internet : échec
