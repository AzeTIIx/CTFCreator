"""Construction de l'environnement docker compose par instance.

La compose.yml d'une box est paramétrée par des variables fournies ici :
  BOX_INDEX, ACCESS_SUBNET, ENTRY_IP, ACCESS_BRIDGE, INTERNAL_BRIDGE, PASV_ADDRESS
Les flags de séance (FLAG_*) viennent de l'environnement de l'enseignant (ou
d'un .env) et sont transmis tels quels au build.
"""

from __future__ import annotations

import os

from .model import Box, Instance


def instance_env(box: Box, inst: Instance, extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env.update({
        "BOX_INDEX": str(inst.index),
        "ACCESS_SUBNET": inst.access_subnet,
        "ENTRY_IP": inst.entry_ip,
        "ACCESS_BRIDGE": inst.bridge_name,
        "INTERNAL_BRIDGE": inst.internal_bridge_name,
        # Pratique pour les box FTP passif : annoncer l'IP d'entrée.
        "PASV_ADDRESS": inst.entry_ip,
    })
    # Transmet les flags déclarés par la box s'ils sont présents dans l'env.
    for flag in box.flags:
        if flag in os.environ:
            env[flag] = os.environ[flag]
    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    return env
