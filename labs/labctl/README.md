# labctl — orchestrateur de box (lab)

Wrapper Python/Rich pour déployer des **box** (challenges de type machine) par
user, à la GOAD : allocation réseau, génération WireGuard, pare-feu, batch.

## Installation
```bash
export LABCTL_BOXES=/chemin/vers/<client>/boxes   # dossier des box du client
cd labs/labctl
python -m venv .venv && . .venv/bin/activate     # (Windows : .venv\Scripts\activate)
pip install -r requirements.txt
```
Binaires attendus **sur la Debian** : `docker`, `wg` (wireguard-tools),
`iptables`, `ufw`. Sur un poste de dev sans ces outils, labctl fonctionne en
mode « génération seule » (alloue, écrit les configs) et le signale.

## Shell interactif (REPL à la GOAD)
```bash
cd labs/labctl && python -m labctl
```
On tape de **vraies commandes** (pas de menu numéroté) ; le prompt indique la
box active : `labctl(s07-s08-intrusion-fil-rouge)>`.

| Commande | Effet |
|---|---|
| `boxes` | liste les box disponibles |
| `use <box>` | sélectionne la box active |
| `add <user> [<user>…]` | alloue un ou plusieurs **users** (sans déployer) |
| `deploy <n>\|<user>\|all` | construit+lance (`deploy 5` = user01..user05) |
| `list` (`status`) | users déployés + état live |
| `endpoint <ip>` | IP publique du VPS (pour WireGuard) |
| `wg <user>` | **affiche la config WireGuard de ce user** ; `wg all` régénère tout |
| `firewall [apply]` | génère (et applique) le cloisonnement |
| `destroy <user>` | détruit l'instance d'un user |
| `new <slug>` | crée une box depuis le template |
| `help [cmd]` · `exit` | aide · quitter |

## Sous-commandes (batch / scripting)
```bash
python -m labctl list
python -m labctl deploy s07-s08-intrusion-fil-rouge -n 8   # crée user01..user08 et déploie
python -m labctl status
python -m labctl wireguard --endpoint 194.163.153.215      # écrit wg0.conf + tous les profils
python -m labctl wireguard user03                          # affiche la config d'un user
python -m labctl firewall --apply
python -m labctl destroy --user user03
python -m labctl new ma-nouvelle-box
```

## Ce que labctl génère (dans `labs/labctl/state/`, gitignoré)
- `deployment.json` : l'état (box, user, index).
- `wg/wg0.conf` : config serveur WireGuard (à copier dans `/etc/wireguard/`).
- `wg/clients/<projet>.conf` : un profil par user (à distribuer).
- `wg/*.key|.pub` : clés (secrets).
- `firewall-lab.gen.sh` : le cloisonnement (à exécuter en root, ou via la unit
  systemd `lab-firewall.service`).

## Flux de déploiement type (sur la Debian)
```bash
export FLAG_RECON=... FLAG_FTP=... ...          # flags de séance (sinon placeholder)
python -m labctl deploy s07-s08-intrusion-fil-rouge -n 8
python -m labctl wireguard --endpoint <IP_PUBLIQUE_VPS>
sudo cp state/wg/wg0.conf /etc/wireguard/wg0.conf && sudo systemctl enable --now wg-quick@wg0
sudo bash state/firewall-lab.gen.sh             # (ou lab-firewall.service)
# distribuer state/wg/clients/*.conf aux users
```
Puis **recette d'isolation** (cf. `labs/lab-network/README.md` §Recette) avant
d'ouvrir aux étudiants : nmap = cible seule ; VPN→hôte, cible→CTFd/DB/dockerproxy/
egress = bloqués.

## Modèle réseau
Un index global `i` par instance → `172.30.<i>.0/24` (accès), `172.30.<i>.10`
(entrée), `10.99.0.<10+i>` (peer VPN), `acc_b<i>` (bridge). Voir
[`../challenges/README.md`](../challenges/README.md).

## Limites
- `wg`/`iptables`/`ufw`/`systemd` = Debian uniquement. Sur Windows/macOS,
  labctl alloue et génère les fichiers, mais n'applique pas le réseau hôte.
- Le pare-feu généré reprend la logique **prouvée** de `labs/lab-network/`
  (UFW + table raw anti-direct-routing Docker + DOCKER-USER par user).
