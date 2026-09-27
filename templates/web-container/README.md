# __SLUG__

Fiche enseignant (exclue de l'image par `.dockerignore`).

- **Faiblesse** : CWE-000 — à décrire (une seule, déclarée dans `security-contract.yaml`)
- **Service** : HTTP sur 1337 dans le conteneur
- **Flag** : `challenge.yml` (identique à l'`ENV FLAG` du Dockerfile)

## Recette locale

```bash
./check_challenge.sh        # build + run durci + tests/exploit_poc.py + tests/security_audit.py
```
