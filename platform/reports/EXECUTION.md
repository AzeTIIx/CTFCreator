# Journal d’exécution réel

Date : 2026-09-14  
Environnement d’exécution de la livraison : **Windows 10** (poste de développement), pas le VPS Debian 12 cible.

## Informations fournies / manquantes

| Donnée | Statut |
|--------|--------|
| VPS_PROVIDER | Manquant (pas de `.env` réel) |
| TARGET_HOST | Manquant |
| ADMIN_SSH_USER | Manquant |
| ADMIN_CIDR | **Supprimé** (admin mobile — SSH any + clés) |

| CTFD_FQDN | Manquant |
| TARGET_DISTRO / VERSION | Manquant (cible documentée : Debian 12) |
| Accès SSH au VPS | Non fourni |
| Cible Linux Debian 12 | Non disponible dans cette session |

## Commandes réellement exécutées (cette session)

| Commande | Code | Résultat |
|----------|------|----------|
| `py -3 -m py_compile …` | 0 | OK |
| `py -3 -m unittest discover -s tests -v` | 0 | 7 tests OK |
| `py -3 scripts/main.py preflight` | 0 | Rapport écrit ; déploiement bloqué ; hors Linux signalé |
| `py -3 scripts/main.py --dry-run deploy` | 2 | Arrêt : variables obligatoires manquantes |
| `py -3 scripts/main.py --dry-run harden-ssh` | 0 | **NON EXÉCUTÉ** (non Linux) |
| `py -3 scripts/main.py --dry-run configure-firewall` | 0 | **NON EXÉCUTÉ** (non Linux) |
| `py -3 scripts/main.py verify` | 1 | **NON CONFORME** (attendu hors cible) |

Rapports générés sous `reports/` (preflight, deploy-blocked, harden-ssh, firewall, verify).

## Non exécuté (honnêtement)

- Durcissement SSH sur cible + validation par **nouvelle connexion**
- Configuration / vérification pare-feu sur cible
- `docker compose up` CTFd sur VPS Debian 12
- Vérification des digests d’images sur la cible
- Sauvegarde puis restauration exercées sur volumes de production
- Redémarrage VPS
- Tests d’isolation d’instances étudiants (N/A en degraded sans instances)
- Installation de tout plugin Docker CTFd

## Décision plugins

- `TheOriginalOrangeJuice/Docker-CTFd-Plugin@1b86917…` : **refusé**
- Aucun plugin **accepté** pour promotion
- Mode opérationnel : **degraded**

## Conclusion livraison

Le dépôt est **exécutable comme outillage** (CLI, Compose épinglé, docs, checks, tests).  
Le déploiement production est **bloqué** jusqu’à :

1. VPS Debian 12 dédié  
2. Fichier `.env` réel (plus les exemples)  
3. Exécution de la séquence preflight → backup → harden-ssh → firewall → deploy → verify sur la cible  
