"""Modèle de données de labctl : box, instances, allocation réseau.

Conventions d'adressage (un index global `i` par instance déployée, 1..244) :
  - réseau d'accès (routé, atteint par le VPN) : 172.30.<i>.0/24
  - IP du service d'entrée (ports réels) ......: 172.30.<i>.10
  - nom du bridge Docker (pour le pare-feu) ...: acc_b<i>
  - réseau interne (non routé) ................: bridge "internal", auto
  - IP du peer WireGuard du binôme ............: 10.99.0.<10+i>
Ces conventions correspondent aux règles prouvées de infra/lab-network/.
Le pur calcul ci-dessous est testable hors Docker/WireGuard.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

WG_SERVER_IP = "10.99.0.1"
WG_SERVER_CIDR = "10.99.0.1/24"
WG_PORT = 51820
LAB_SUPERNET = "172.30.0.0/16"
DOCKER_SUPERNET = "172.16.0.0/12"
MAX_INDEX = 244  # 10 + i <= 254

# Peer "admin" : un seul profil qui route TOUT le lab (172.30.0.0/16) pour
# tester chaque box depuis une seule Exegol. Le pare-feu lui accorde l'accès
# à tout le supernet (contrairement aux users, limités à leur /24).
ADMIN_USER = "admin"
ADMIN_WG_IP = "10.99.0.2"


class LabctlError(RuntimeError):
    pass


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not s:
        raise LabctlError(f"nom invalide: {name!r}")
    return s


@dataclass
class Box:
    """Une box = un challenge de type machine, décrit par box.yml."""
    name: str
    path: Path
    title: str = ""
    entry_service: str = "gateway"
    entry_ip_offset: int = 10
    ports: list[int] = field(default_factory=lambda: [22])
    compose: str = "compose.yml"
    prebuild: str | None = None
    flags: list[str] = field(default_factory=list)
    ssh_user: str = ""            # compte pour l'accès étudiant (info/README)
    description: str = ""

    @property
    def slug(self) -> str:
        return slugify(self.name)

    @property
    def compose_path(self) -> Path:
        return self.path / self.compose


@dataclass
class Instance:
    """Une instance déployée d'une box pour un binôme, à l'index global i."""
    box: str
    user: str          # étiquette du binôme, ex. "binome01"
    index: int

    def _check(self) -> None:
        if not (1 <= self.index <= MAX_INDEX):
            raise LabctlError(f"index {self.index} hors plage 1..{MAX_INDEX}")

    @property
    def project(self) -> str:
        return f"lab-{slugify(self.box)}-{slugify(self.user)}"

    @property
    def access_subnet(self) -> str:
        self._check()
        return f"172.30.{self.index}.0/24"

    @property
    def entry_ip(self) -> str:
        self._check()
        return f"172.30.{self.index}.10"

    @property
    def bridge_name(self) -> str:
        self._check()
        return f"acc_b{self.index}"

    @property
    def internal_bridge_name(self) -> str:
        self._check()
        return f"int_b{self.index}"

    @property
    def wg_peer_ip(self) -> str:
        self._check()
        return f"10.99.0.{10 + self.index}"

    def to_dict(self) -> dict:
        return {"box": self.box, "user": self.user, "index": self.index}

    @classmethod
    def from_dict(cls, d: dict) -> "Instance":
        return cls(box=d["box"], user=d["user"], index=int(d["index"]))


@dataclass
class Deployment:
    """État global : l'ensemble des instances déployées (persisté en JSON)."""
    instances: list[Instance] = field(default_factory=list)

    def used_indices(self) -> set[int]:
        return {i.index for i in self.instances}

    def next_index(self) -> int:
        used = self.used_indices()
        for i in range(1, MAX_INDEX + 1):
            if i not in used:
                return i
        raise LabctlError("plus d'index disponible (max atteint)")

    def find(self, box: str, user: str) -> Instance | None:
        for inst in self.instances:
            if inst.box == box and inst.user == user:
                return inst
        return None

    def add(self, box: str, user: str) -> Instance:
        existing = self.find(box, user)
        if existing:
            return existing
        inst = Instance(box=box, user=user, index=self.next_index())
        self.instances.append(inst)
        return inst

    def remove(self, box: str, user: str) -> Instance | None:
        inst = self.find(box, user)
        if inst:
            self.instances.remove(inst)
        return inst

    def for_box(self, box: str) -> list["Instance"]:
        return [i for i in self.instances if i.box == box]

    def to_dict(self) -> dict:
        return {"instances": [i.to_dict() for i in self.instances]}

    @classmethod
    def from_dict(cls, d: dict) -> "Deployment":
        return cls(instances=[Instance.from_dict(x) for x in d.get("instances", [])])


def validate_no_overlap(deploy: Deployment) -> None:
    """Garde-fou : aucun index/sous-réseau/peer VPN en double."""
    seen_idx: set[int] = set()
    seen_net: set[str] = set()
    for inst in deploy.instances:
        if inst.index in seen_idx:
            raise LabctlError(f"index dupliqué: {inst.index}")
        net = inst.access_subnet
        if net in seen_net:
            raise LabctlError(f"sous-réseau dupliqué: {net}")
        # cohérence avec le supernet lab
        if ipaddress.ip_network(net).subnet_of(ipaddress.ip_network(LAB_SUPERNET)) is False:
            raise LabctlError(f"{net} hors du supernet lab {LAB_SUPERNET}")
        seen_idx.add(inst.index)
        seen_net.add(net)
