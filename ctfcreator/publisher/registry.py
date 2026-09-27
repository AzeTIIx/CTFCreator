"""Local Docker registry management."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .docker_cli import CommandResult, DockerCLI
from .logging_utils import get_registry_logger
from .models import PublishConfig


class RegistryError(Exception):
    """Registry operation failure."""

    def __init__(self, message: str, step: str = ""):
        self.step = step
        super().__init__(message)


@dataclass
class RegistryHealth:
    healthy: bool
    message: str = ""


MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.oci.image.manifest.v1+json"
)


class RegistryClient:
    """HTTP client for Docker Registry V2 API."""

    def __init__(self, registry: str, timeout: float = 5.0):
        self.registry = registry
        self.timeout = timeout
        host = registry.split(":")[0]
        port = registry.split(":")[1] if ":" in registry else "5000"
        self.base_url = f"http://{host}:{port}"

    def check_health(self) -> RegistryHealth:
        try:
            req = urllib.request.Request(f"{self.base_url}/v2/", method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return RegistryHealth(healthy=True, message="Registry V2 healthy")
                return RegistryHealth(healthy=False, message=f"Unexpected status: {resp.status}")
        except urllib.error.HTTPError as e:
            if e.code in (200, 401):
                return RegistryHealth(healthy=True, message="Registry V2 responding")
            return RegistryHealth(healthy=False, message=f"HTTP {e.code}: {e.reason}")
        except Exception as e:
            return RegistryHealth(healthy=False, message=str(e))

    def get_tag_digest(self, repository: str, tag: str) -> str | None:
        """Get digest for a tag via manifest HEAD request."""
        url = f"{self.base_url}/v2/{repository}/manifests/{tag}"
        req = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "Accept": MANIFEST_ACCEPT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                digest = resp.headers.get("Docker-Content-Digest")
                return digest
        except urllib.error.HTTPError:
            return None
        except Exception:
            return None

    def tag_exists(self, repository: str, tag: str) -> bool:
        return self.get_tag_digest(repository, tag) is not None

    def list_catalog(self) -> list[str]:
        try:
            req = urllib.request.Request(f"{self.base_url}/v2/_catalog", method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                import json
                data = json.loads(resp.read().decode())
                return data.get("repositories", [])
        except Exception:
            return []


def wait_for_registry(
    client: RegistryClient,
    *,
    max_retries: int = 30,
    interval: float = 1.0,
) -> RegistryHealth:
    """Wait for registry to become healthy."""
    last = RegistryHealth(healthy=False, message="Not yet available")
    for _ in range(max_retries):
        last = client.check_health()
        if last.healthy:
            return last
        time.sleep(interval)
    return last


def ensure_registry(config: PublishConfig, docker: DockerCLI) -> RegistryHealth:
    """Ensure local registry is available following idempotent algorithm."""
    log = get_registry_logger()
    if config.dry_run:
        return RegistryHealth(healthy=True, message="Dry-run: skipping registry creation")

    client = RegistryClient(config.registry)

    # Step 1: test registry health
    health = client.check_health()
    if health.healthy:
        log.info("Registry %s is ready", config.registry)
        return health

    # Step 3: find existing container
    if docker.container_exists(config.registry_name):
        log.info("Found registry container: %s", config.registry_name)
        if not docker.container_is_running(config.registry_name):
            log.info("Starting stopped registry container: %s", config.registry_name)
            # Step 4: start stopped compatible container
            inspect = docker.container_inspect(config.registry_name)
            if inspect:
                ports = inspect.get("HostConfig", {}).get("PortBindings", {})
                expected = f"{config.bind_address}:{config.registry_port}"
                port_ok = False
                for binding in ports.get("5000/tcp", []):
                    host_ip = binding.get("HostIp", "")
                    host_port = binding.get("HostPort", "")
                    if f"{host_ip}:{host_port}" == expected or host_port == str(config.registry_port):
                        port_ok = True
                if not port_ok:
                    raise RegistryError(
                        f"Container {config.registry_name} exists but port binding incompatible",
                        step="registry-inspect",
                    )
            result = docker.docker("start", config.registry_name)
            if result.returncode != 0:
                raise RegistryError(
                    f"Failed to start registry container: {result.stderr}",
                    step="registry-start",
                )
            health = wait_for_registry(client)
            if health.healthy:
                log.info("Registry is healthy")
                return health
            raise RegistryError(
                f"Container running but registry unhealthy: {health.message}",
                step="registry-health",
            )
        else:
            # Step 5: running but not healthy
            raise RegistryError(
                f"Container {config.registry_name} running but registry unhealthy: {health.message}",
                step="registry-health",
            )

    # Step 6: create registry
    if config.no_create_registry:
        raise RegistryError(
            "Registry not available and --no-create-registry set",
            step="registry-create",
        )

    log.info(
        "Creating local registry %s on %s:%s",
        config.registry_name,
        config.bind_address,
        config.registry_port,
    )
    bind = f"{config.bind_address}:{config.registry_port}:5000"
    result = docker.docker(
        "run", "-d",
        "--restart", "unless-stopped",
        "--name", config.registry_name,
        "-p", bind,
        "-v", f"{config.registry_volume}:/var/lib/registry",
        config.registry_image,
    )
    if result.returncode != 0:
        raise RegistryError(
            f"Failed to create registry: {result.stderr}",
            step="registry-create",
        )

    # Step 7: wait for availability
    health = wait_for_registry(client)
    if not health.healthy:
        raise RegistryError(
            f"Registry created but not healthy after retries: {health.message}",
            step="registry-health",
        )
    log.info("Registry is healthy")
    return health


def check_immutability(
    client: RegistryClient,
    repository: str,
    tag: str,
    local_digest: str,
    *,
    docker: DockerCLI | None = None,
    local_reference: str | None = None,
    force: bool = False,
) -> tuple[str, bool, str | None]:
    """
    Check tag immutability.
    Returns (action, is_idempotent, remote_digest).
    action: 'push' | 'skip' | 'block'
    """
    remote = client.get_tag_digest(repository, tag)
    if remote is None:
        return ("push", False, None)

    if docker is not None and local_reference is not None:
        return _check_immutability_by_config(
            client, repository, tag, local_reference, docker, remote, force=force
        )

    local_normalized = local_digest.split("@")[-1] if "@" in local_digest else local_digest
    remote_normalized = remote.split("@")[-1] if "@" in remote else remote

    if local_normalized == remote_normalized:
        return ("skip", True, remote)

    if force:
        return ("push", False, remote)

    return ("block", False, remote)


def _check_immutability_by_config(
    client: RegistryClient,
    repository: str,
    tag: str,
    local_reference: str,
    docker: DockerCLI,
    remote_manifest: str,
    *,
    force: bool = False,
) -> tuple[str, bool, str | None]:
    """Compare local and remote images by config digest after pulling remote."""
    backup_ref = f"{local_reference}-__local_backup__"
    remote_ref = f"{client.registry}/{repository}:{tag}"

    local_inspect = docker.inspect_image(local_reference)
    if not local_inspect:
        return ("push", False, remote_manifest)

    docker.docker("tag", local_reference, backup_ref)

    pull = docker.docker("pull", remote_ref)
    if pull.returncode != 0:
        docker.docker("tag", backup_ref, local_reference)
        docker.docker("rmi", backup_ref)
        return ("push", False, remote_manifest)

    remote_inspect = docker.inspect_image(remote_ref)
    local_backup = docker.inspect_image(backup_ref)
    remote_config = (remote_inspect or {}).get("Id", "")
    local_config = (local_backup or {}).get("Id", "")

    docker.docker("tag", backup_ref, local_reference)
    docker.docker("rmi", backup_ref)

    if local_config and local_config == remote_config:
        return ("skip", True, remote_manifest)

    if force:
        return ("push", False, remote_manifest)

    return ("block", False, remote_manifest)
