# lab-network — isolation « une IP/segment par binôme » (modèle Exegol/HTB)

Déploiement des cibles de challenge d'intrusion avec **une IP dédiée et un
segment réseau isolé par binôme**, accès étudiant par **WireGuard**, sur un
**VPS Debian 12 unique** qui héberge aussi CTFd. ≤ 10 binômes.

Objectif : un `nmap` d'un étudiant sur **sa** cible ne voit **que** ses 3
services (21/22/80) — jamais ton SSH admin, ton CTFd, le registre, ni une
instance voisine.

## Ce qui est validé, ce qui ne l'est pas

| Brique | Statut |
|--------|--------|
| 1. Cible isolée à IP dédiée + vrais ports 21/22/80 (`docker-compose.target.yml`) | **Validé en local** (Docker) : parcours complet joué depuis un attaquant placé sur le segment, cf. ci-dessous |
| 2. WireGuard (`wireguard/`) | **À recetter sur la Debian** — non testé (poste de dev Windows) |
| 3. Pare-feu / cloisonnement (`firewall-lab.sh`) | **À recetter sur la Debian** — non testé |

Ne déclare pas l'isolation acquise tant que la recette §Recette n'est pas
passée sur la cible avec sorties de commande à l'appui.

## Plan d'adressage

```
Hôte Debian (IP publique unique)
├── eth0 : CTFd 80/443, SSH admin 22            (réseau infra — hors lab)
├── wg0  : 10.99.0.1/24, udp/51820              (entrée VPN, 1 peer/binôme)
│      binôme b → peer 10.99.0.(10+b)
└── par binôme b :
      access_b<b>   172.30.<b>.0/24  (routé)  → gateway 172.30.<b>.10 : 21/22/80
      internal_b<b> internal:true             → intranet (jamais routé)
```

Règles de flux (imposées par `firewall-lab.sh`, chaîne DOCKER-USER + INPUT) :
- peer `10.99.0.(10+b)` → `172.30.<b>.0/24` : **ACCEPT** (sa seule cible) ;
- VPN → autre `172.30.*`, → hôte (22/80/443/5000/3306/6379) : **DROP** ;
- cibles → Internet, → hôte : **DROP** (egress coupé).

## Pourquoi ce modèle règle les points durs

- **Vrais ports 21/22/80** : une IP par cible ⇒ plus aucune collision, plus de
  ports éphémères ni de PASV bricolé. `docker-compose.target.yml` ne publie
  **rien** sur l'hôte (`ports:` absent) : la gateway écoute sur son IP dédiée,
  atteinte par routage depuis le tunnel.
- **Pas de collision avec ton SSH/CTFd** : le `sshd` de la cible est en `22`
  sur `172.30.<b>.10`, pas sur l'IP publique de l'hôte.
- **FTP passif trivial** : `PASV_ADDRESS=172.30.<b>.10` (fixé par le compose).
- **Périmètre tenable** : le VPN ne route que le /24 de la cible ; le pare-feu
  interdit le reste.

## Déploiement (sur la Debian)

Prérequis : Docker + `wireguard-tools` installés ; images du challenge
constructibles (contexte relatif vers `../deploy_challenges/challenges/…`).

1. **Serveur WireGuard**
   ```bash
   wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
   cp wireguard/wg0.conf.example /etc/wireguard/wg0.conf   # y coller la clé privée serveur
   systemctl enable --now wg-quick@wg0
   ```
2. **Cibles + peers, un binôme à la fois**
   ```bash
   ./provision-binome.sh 1 <IP_PUBLIQUE_VPS>
   # coller le bloc [Peer] affiché dans /etc/wireguard/wg0.conf, puis :
   wg syncconf wg0 <(wg-quick strip wg0)
   # remettre ./out/binome01.conf AU binôme 1
   ```
   Répéter pour chaque binôme (2, 3, …). Pour cuire des flags de séance,
   `export FLAG_RECON=… FLAG_FTP=… …` avant l'appel.
3. **Pare-feu** (après avoir lancé toutes les cibles)
   ```bash
   sudo NB_BINOMES=<N> ./firewall-lab.sh
   # rendre persistant : netfilter-persistent save  (ou une unit systemd)
   ```

## Recette (à faire sur la Debian, garder les sorties)

Depuis le Kali d'un binôme de test connecté au VPN :

1. `nmap -Pn 172.30.1.10` → **seuls** 21/22/80 ouverts.
2. Parcours complet des 7 jalons jouable (comme validé en local).
3. `nmap -Pn <IP_PUBLIQUE_VPS>` (ou tentative vers l'hôte) → **CTFd 80 / SSH 22
   injoignables** depuis le tunnel.
4. Tentative vers `172.30.2.10` (autre binôme) → **injoignable**.
5. Depuis la cible (via le shell obtenu) : `curl https://example.com` → **egress
   coupé** (timeout).
6. Depuis la cible : tentative vers l'hôte (CTFd/registre/DB) → **injoignable**.
7. **Inter-bridge (LE point critique sur mono-VPS)** — depuis le shell root de
   la cible, tenter de joindre les conteneurs de l'infra sur leurs IP de bridge.
   IP relevées sur ce déploiement (à revérifier, elles peuvent changer) :
   ```bash
   curl -s -m5 http://172.21.0.3/     # nginx/CTFd    -> doit échouer
   curl -s -m5 http://172.19.0.2:8000 # CTFd direct   -> doit échouer
   nc -z -w3 172.20.0.2 3306          # MariaDB       -> doit échouer
   nc -z -w3 172.18.0.2 6379          # Redis         -> doit échouer
   nc -z -w3 172.17.0.2 5000          # registre      -> doit échouer
   nc -z -w3 172.22.0.2 2375          # ⚠ dockerproxy -> doit échouer (évasion)
   ```
   → **tous injoignables** (règle 1e, `172.30.0.0/16 → 172.16.0.0/12` DROP).
   Le plus grave si ça passe : `dockerproxy` (172.22.0.2) = pilotage de l'API
   Docker de l'hôte depuis une cible compromise. Relève les IP à jour avant :
   `docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' $(docker ps -q)`.

Tant qu'un de ces points échoue, ne pas ouvrir aux étudiants.

> Note mono-VPS : tes services (CTFd/DB/Redis/registre) sont sur les bridges
> `172.17`–`172.22`. La règle 1e bloque tout `172.30.x → 172.16.0.0/12`, donc
> une cible compromise ne peut atteindre ni tes conteneurs ni un autre binôme.
> Adapte `HOST_SVC_PORTS` (ajoute `8000` si CTFd écoute en direct) dans
> `firewall-lab.sh`. IPv6 : le lab n'en a pas ; durcis l'hôte séparément si tu
> veux couvrir l'accès IPv6 public à CTFd/SSH.

## Validation locale déjà réalisée (brique 1)

Sur Docker (poste de dev), la cible en mode labo a été jouée **de bout en
bout** depuis un conteneur attaquant placé sur `access_b1` :

- `nmap 172.30.1.10` → seuls 21/22/80 ouverts ;
- 7 jalons validés (`AFLO{local_test_only}`) via les **vrais ports** 21/22/80,
  FTP passif inclus (`PASV_ADDRESS=172.30.1.10`), rebond SSH `-L` vers
  `intranet` ;
- cible du binôme 2 (`172.30.2.10`) déjà `filtered` depuis le segment du
  binôme 1 grâce à l'isolation Docker par défaut (le pare-feu la renforce et
  couvre les chemins VPN/hôte/egress que Docker ne couvre pas).

## Fichiers

- `docker-compose.target.yml` — cible en mode labo (IP dédiée, vrais ports).
- `provision-binome.sh` — provisionne un binôme (cible + peer WireGuard).
- `firewall-lab.sh` — cloisonnement DOCKER-USER + INPUT.
- `wireguard/wg0.conf.example`, `wireguard/client.conf.template`.
