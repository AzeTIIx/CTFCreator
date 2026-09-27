# Supervision

cAdvisor + node_exporter + Prometheus + Grafana, projet Compose `monitoring`, indépendant de la stack CTFd.

```bash
cd /opt/CTFCreator/platform/monitoring
sudo ./install.sh --ssh-tunnel "azetix denis fafanellu"
# depuis le poste :
ssh -N -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 azetix@<vps>
```

- Aucun port public : Grafana `127.0.0.1:3000`, Prometheus `127.0.0.1:9090`. cAdvisor et node_exporter ne sont joignables que sur le réseau Docker `monitoring`.
- Instances challenge repérées par le nom `chal-u<user>-c<chal>-<ts>` (plugin 0xfbad) ; Prometheus en extrait `ctf_user` et `ctf_chal`.
- Règles : `prometheus/rules/ctf.yml` (hôte, stack CTFd, instances : saturation CPU, RAM, egress, absence de limites, PIDs). Pas de notification sortante sans Alertmanager.
- Le tunnel SSH ajoute `/etc/ssh/sshd_config.d/60-monitoring-tunnel.conf` : `AllowTcpForwarding local` + `PermitOpen` limité à 3000/9090 pour les utilisateurs listés ; le reste du durcissement est inchangé (vérifié par `sshd -T` avant reload, rollback sinon).
- cAdvisor est `privileged` avec `/var/run` monté : équivalent root, exigence amont.
- Rétention Prometheus : 15 j / 2 Go (`PROM_RETENTION_TIME`, `PROM_RETENTION_SIZE` dans `.env`).
- Désinstallation : `docker compose -p monitoring down` (ajouter `-v` pour supprimer l'historique).
