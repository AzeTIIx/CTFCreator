"""labctl — orchestrateur de box (challenges de type machine) pour le lab."""
__version__ = "0.1.0"


def configure(boxes_root=None, state_dir=None) -> None:
    """Redirige labctl à l'exécution (utilisé par CTFCreator) :
    - boxes_root : dossier des box de l'événement courant ;
    - state_dir  : état (instances, clés WireGuard) — ressource du VPS, commune aux événements."""
    from pathlib import Path

    from . import discovery, state

    if boxes_root is not None:
        discovery.CHALLENGES_ROOT = Path(boxes_root).resolve()
    if state_dir is not None:
        state.STATE_DIR = Path(state_dir).resolve()
        state.DEPLOY_FILE = state.STATE_DIR / "deployment.json"
        state.SETTINGS_FILE = state.STATE_DIR / "settings.json"
        state.WG_DIR = state.STATE_DIR / "wg"
        state.WG_CLIENTS_DIR = state.WG_DIR / "clients"
