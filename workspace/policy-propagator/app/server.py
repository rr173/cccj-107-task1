"""Zero-dependency HTTP layer (stdlib http.server) around service.py."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import db, service


class Handler(BaseHTTPRequestHandler):
    server_version = "PolicyPropagator/1.0"

    def log_message(self, fmt, *args):
        print("[ctrl] " + fmt % args, flush=True)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise service.DomainError("invalid JSON body")

    def _send(self, code: int, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, fn):
        try:
            self._send(200, fn())
        except service.DomainError as e:
            self._send(e.status, {"error": str(e)})
        except Exception:
            import traceback
            traceback.print_exc()
            self._send(500, {"error": "internal error"})

    # ---- routing --------------------------------------------------------
    def do_GET(self):
        p = self.path
        if p == "/health":
            return self._send(200, {"ok": True})
        if p == "/scopes":
            return self._handle(service.list_scopes)
        if p == "/versions" or p.startswith("/versions?scope="):
            scope = p.split("scope=", 1)[1] if "scope=" in p else None
            return self._handle(lambda: service.list_versions(scope))
        if p.startswith("/versions/"):
            vid = p.rsplit("/", 1)[1]
            return self._handle(lambda: service.get_version(vid))
        if p == "/nodes":
            return self._handle(service.list_nodes)
        if p.startswith("/nodes/"):
            nid = p.rsplit("/", 1)[1]
            return self._handle(lambda: service.get_node(nid))
        if p.startswith("/blobs/"):
            vid = p.rsplit("/", 1)[1]
            try:
                data = service.blob_bytes(vid)
            except service.DomainError as e:
                return self._send(e.status, {"error": str(e)})
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        p = self.path
        try:
            body = self._read_json()
        except service.DomainError as e:
            return self._send(e.status, {"error": str(e)})

        if p == "/scopes":
            return self._handle(lambda: self._mk_scope(body))
        if p == "/versions":
            return self._handle(lambda: service.publish(body))
        if p == "/nodes":
            return self._handle(lambda: service.register_node(
                body.get("node_id"), body.get("region")))
        if p.startswith("/versions/") and p.endswith("/revoke"):
            vid = p.split("/")[2]
            return self._handle(lambda: service.revoke(vid))
        if p.startswith("/nodes/") and p.endswith("/poll"):
            nid = p.split("/")[2]
            return self._handle(lambda: service.poll(nid, body))
        if p.startswith("/nodes/") and p.endswith("/receipts"):
            nid = p.split("/")[2]
            return self._handle(lambda: service.receipt(nid, body))
        self._send(404, {"error": "not found"})

    def _mk_scope(self, body):
        name = body.get("name")
        if not name:
            raise service.DomainError("name required")
        with db.lock():
            db.conn().execute(
                "INSERT OR IGNORE INTO scopes(name, created_at) VALUES(?,?)",
                (name, service.now()))
            db.conn().commit()
        return {"name": name}


def make_server(host="0.0.0.0", port=8080):
    db.init_db()
    return ThreadingHTTPServer((host, port), Handler)
