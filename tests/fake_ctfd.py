"""Faux CTFd (sous-ensemble de l'API v1 utilisé par CTFCreator) pour les tests."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "ctfd_test_token"
CHALLENGE_FIELDS = {
    "name", "category", "description", "connection_info", "value", "state", "type", "function",
    "initial", "minimum", "decay", "max_attempts", "image", "port", "ctype", "command", "volumes",
    "cap_add", "ssh_username", "expiration_seconds", "max_renewals", "max_memory_mb", "max_cpu",
    "docker_context",
}


class State:
    def __init__(self):
        self.challenges: dict[int, dict] = {}
        self.children: dict[str, dict[int, dict]] = {"flags": {}, "tags": {}, "hints": {}, "files": {}}
        self.next_id = 1
        self.requests: list[tuple[str, str]] = []
        self.link_key = "challenge_id"  # clé de rattachement acceptée (simule les versions du schéma)

    def nid(self) -> int:
        self.next_id += 1
        return self.next_id

    def add_challenge(self, **fields) -> int:
        cid = self.nid()
        self.challenges[cid] = {"id": cid, "state": "hidden", "type": "standard", **fields}
        return cid

    def add_child(self, kind: str, cid: int, **fields) -> int:
        oid = self.nid()
        self.children[kind][oid] = {"id": oid, "challenge_id": cid, **fields}
        return oid

    def of(self, kind: str, cid: int) -> list[dict]:
        return [o for o in self.children[kind].values() if o["challenge_id"] == cid]


def make_server(state: State) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, doc: dict) -> None:
            body = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _ok(self, data=None):
            self._send(200, {"success": True, "data": data})

        def _auth(self) -> bool:
            state.requests.append((self.command, self.path))
            # comme CTFd : le jeton n'est pris en compte qu'avec Content-Type JSON (sauf upload multipart)
            ctype = self.headers.get("Content-Type", "")
            if self.headers.get("Authorization") != f"Token {TOKEN}" or not (
                ctype.startswith(("application/json", "multipart/form-data"))
            ):
                self._send(403, {"success": False, "errors": "forbidden"})
                return False
            return True

        def _json(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if not self._auth():
                return
            if self.path == "/api/v1/challenges?view=admin":
                return self._ok([{k: c.get(k) for k in ("id", "name", "type", "category", "value")} for c in state.challenges.values()])
            m = re.fullmatch(r"/api/v1/challenges/(\d+)\?view=admin", self.path)
            if m:
                return self._ok(state.challenges[int(m.group(1))])
            m = re.fullmatch(r"/api/v1/challenges/(\d+)/(flags|tags|hints|files)", self.path)
            if m:
                return self._ok(state.of(m.group(2), int(m.group(1))))
            self._send(404, {"success": False})

        def do_POST(self):
            if not self._auth():
                return
            if self.path == "/api/v1/challenges":
                body = self._json()
                unknown = set(body) - CHALLENGE_FIELDS
                if unknown:  # le modèle SQLAlchemy refuse les clés inconnues
                    return self._send(400, {"success": False, "errors": f"unknown {sorted(unknown)}"})
                cid = state.add_challenge(**body)
                return self._ok(state.challenges[cid])
            m = re.fullmatch(r"/api/v1/(flags|tags|hints)", self.path)
            if m:
                body = self._json()
                if state.link_key not in body:
                    return self._send(400, {"success": False, "errors": "missing link"})
                cid = int(body.pop(state.link_key))
                oid = state.add_child(m.group(1), cid, **body)
                return self._ok(state.children[m.group(1)][oid])
            if self.path == "/api/v1/files":
                n = int(self.headers["Content-Length"])
                raw = self.rfile.read(n).decode(errors="replace")
                cid = int(re.search(r'name="challenge_id"\r\n\r\n(\d+)', raw).group(1))
                fname = re.search(r'filename="([^"]+)"', raw).group(1)
                oid = state.add_child("files", cid, type="challenge", location=f"abc123/{fname}")
                return self._ok([state.children["files"][oid]])
            self._send(404, {"success": False})

        def do_PATCH(self):
            if not self._auth():
                return
            m = re.fullmatch(r"/api/v1/challenges/(\d+)", self.path)
            if not m:
                return self._send(404, {"success": False})
            state.challenges[int(m.group(1))].update(self._json())
            self._ok(state.challenges[int(m.group(1))])

        def do_DELETE(self):
            if not self._auth():
                return
            m = re.fullmatch(r"/api/v1/(flags|tags|hints|files)/(\d+)", self.path)
            if not m:
                return self._send(404, {"success": False})
            state.children[m.group(1)].pop(int(m.group(2)), None)
            self._ok()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
