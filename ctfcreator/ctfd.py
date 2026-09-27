"""Client minimal de l'API REST CTFd v1 (stdlib uniquement).

Authentification : jeton admin (Settings -> Access Tokens), en-tête `Authorization: Token …`.
"""

from __future__ import annotations

import json
import mimetypes
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


class CTFdError(Exception):
    pass


class CTFdClient:
    def __init__(self, url: str, token: str, timeout: float = 30.0):
        self.base = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # ------------------------------------------------------------------ transport

    def _request(self, method: str, path: str, body: bytes | None, content_type: str | None) -> Any:
        headers = {"Authorization": f"Token {self.token}", "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                final_url = resp.geturl()
        except urllib.error.HTTPError as e:
            detail = e.read()[:400].decode(errors="replace")
            raise CTFdError(f"{method} {path} -> HTTP {e.code} {detail}") from None
        except urllib.error.URLError as e:
            raise CTFdError(f"{method} {path} -> {e.reason}") from None
        try:
            doc = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            hint = ""
            if "/login" in final_url or "/setup" in final_url:
                hint = f" : redirigé vers {final_url} — jeton refusé ou absent"
            raise CTFdError(f"{method} {path} -> réponse non JSON{hint} (jeton admin valide ? URL correcte ?)") from None
        if isinstance(doc, dict) and doc.get("success") is False:
            raise CTFdError(f"{method} {path} -> {doc.get('errors') or doc}")
        return doc

    def call(self, method: str, path: str, payload: dict | None = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        # CTFd n'authentifie un jeton que si la requête porte Content-Type: application/json,
        # y compris pour un GET sans corps (sinon : requête anonyme -> redirection /login).
        return self._request(method, path, body, "application/json")

    def data(self, method: str, path: str, payload: dict | None = None) -> Any:
        return self.call(method, path, payload).get("data")

    # ------------------------------------------------------------------ ressources

    def challenges(self) -> list[dict]:
        return self.data("GET", "/api/v1/challenges?view=admin") or []

    def challenge(self, cid: int) -> dict:
        return self.data("GET", f"/api/v1/challenges/{cid}?view=admin") or {}

    def create_challenge(self, payload: dict) -> dict:
        return self.data("POST", "/api/v1/challenges", payload) or {}

    def update_challenge(self, cid: int, payload: dict) -> dict:
        return self.data("PATCH", f"/api/v1/challenges/{cid}", payload) or {}

    def sub(self, cid: int, kind: str) -> list[dict]:
        """kind : flags | tags | hints | files"""
        return self.data("GET", f"/api/v1/challenges/{cid}/{kind}") or []

    def _post_linked(self, path: str, cid: int, base: dict) -> dict:
        """POST d'un objet rattaché à un challenge.

        Selon la version du schéma marshmallow de CTFd, la clé de rattachement est
        `challenge_id` ou `challenge` : on tente la première, puis la seconde sur HTTP 400."""
        try:
            return self.data("POST", path, {"challenge_id": cid, **base}) or {}
        except CTFdError as first:
            if "HTTP 400" not in str(first):
                raise
            return self.data("POST", path, {"challenge": cid, **base}) or {}

    def create_flag(self, cid: int, content: str, ftype: str, data: str) -> dict:
        return self._post_linked("/api/v1/flags", cid, {"type": ftype, "content": content, "data": data})

    def create_tag(self, cid: int, value: str) -> dict:
        return self._post_linked("/api/v1/tags", cid, {"value": value})

    def create_hint(self, cid: int, content: str, cost: int) -> dict:
        return self._post_linked("/api/v1/hints", cid, {"content": content, "cost": cost})

    def delete(self, kind: str, obj_id: int) -> None:
        """kind : flags | tags | hints | files"""
        self.call("DELETE", f"/api/v1/{kind}/{obj_id}")

    def upload_file(self, cid: int, path: Path) -> Any:
        boundary = uuid.uuid4().hex
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        parts = [
            (f'--{boundary}\r\nContent-Disposition: form-data; name="challenge_id"\r\n\r\n{cid}\r\n').encode(),
            (f'--{boundary}\r\nContent-Disposition: form-data; name="challenge"\r\n\r\n{cid}\r\n').encode(),
            (f'--{boundary}\r\nContent-Disposition: form-data; name="type"\r\n\r\nchallenge\r\n').encode(),
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n"
            ).encode() + path.read_bytes() + b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
        return self._request("POST", "/api/v1/files", b"".join(parts), f"multipart/form-data; boundary={boundary}")


_MANIFEST_TYPES = (
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.oci.image.index.v1+json"
)


def registry_has_image(reference: str, timeout: float = 5.0) -> bool | None:
    """Vérifie `host:port/repo:tag` via l'API registry v2 (HTTP, loopback).

    Retourne None si la référence n'est pas vérifiable (registre distant / sans port)."""
    if "/" not in reference or ":" not in reference.rsplit("/", 1)[1]:
        return None
    host, rest = reference.split("/", 1)
    if not host.startswith(("localhost", "127.0.0.1")):
        return None
    repo, tag = rest.rsplit(":", 1)
    req = urllib.request.Request(
        f"http://{host}/v2/{repo}/manifests/{tag}",
        method="HEAD",
        headers={"Accept": _MANIFEST_TYPES},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except urllib.error.URLError:
        return None
