# Réponse à incident

## Principes

1. Préserver les preuves (logs, volumes) — pas de `docker system prune`
2. Couper l’exposition (pare-feu / stop compose) sans détruire les données
3. Communiquer le périmètre : étudiants / admin / Internet
4. Restaurer depuis sauvegarde testée

## Scénarios

### Perte d’accès SSH après durcissement

1. Console fournisseur VPS
2. Restaurer `/var/backups/course-ctfd/sshd/<stamp>/`
3. `sshd -t && systemctl reload ssh`
4. Documenter dans `reports/`

### Fuite suspecte de secret

1. Révoquer / rotation immédiate (SECRET_KEY, DB, Redis, admin CTFd)
2. Invalider sessions
3. Auditer `config/ctfd.env` permissions (0600)
4. Vérifier que les logs scripts ne contiennent pas de secret (`***REDACTED***`)

### Conteneur challenge anormal (futur plugin)

1. Stop du conteneur concerné uniquement
2. Conserver logs
3. Vérifier réseaux / caps / mounts
4. Ne pas toucher aux volumes CTFd sans besoin

### Indisponibilité CTFd

1. `docker compose ps` / health HTTP
2. Restauration backup si corruption
3. Rollback compose stop si nécessaire

## Contacts

Renseigner hors dépôt : responsable cours, hébergeur, contact urgence.

## Hors périmètre étudiants

Tout scan/attaque hors instance attribuée = incident pédagogique / disciplinaire selon charte du cours.
