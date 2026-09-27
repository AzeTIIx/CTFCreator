# Recette manuelle de vérification (cible Debian 12)

Ne cocher comme OK que ce qui a été **réellement** observé. Ne jamais simuler.

## Avant prod étudiants

- [ ] `preflight` OK sur le VPS
- [ ] `.env` réel (plus d’exemple)
- [ ] `backup` réalisé
- [ ] SSH : nouvelle connexion avec clé après `harden-ssh`
- [ ] SSH password : échec
- [ ] SSH depuis un autre réseau (déplacement) : OK avec clé
- [ ] Pare-feu : ports attendus uniquement (22/80/443 ; pas 5000/3306/6379 publics)
- [ ] HTTPS + certificat valides (si TLS activé)
- [ ] Compte fictif créé / connexion CTFd
- [ ] Challenge **statique** créé et consulté
- [ ] Mode degraded : **pas** d’instance plugin
- [ ] Si un jour plugin accepté : start/stop/expire/reset/nettoyage
- [ ] Si plugin : deux instances simultanées isolées
- [ ] Si plugin : pas d’accès hôte / registre / CTFd DB / Internet
- [ ] Si plugin : limites CPU/mem/PID observées
- [ ] Absence de flag réel dans images/journaux
- [ ] Restauration backup testée
- [ ] Redémarrage VPS puis stack healthy
- [ ] Rollback SSH testé (lab) ou documenté

## Critère

Une case non cochée ou un test échoué ⇒ déploiement **non conforme**.
