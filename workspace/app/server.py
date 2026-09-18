"""控制面 HTTP 服务（标准库实现）。

路由：
  POST /v1/scopes                 声明作用域及父作用域
  POST /v1/versions               发布版本（普通 / 紧急覆盖）
  POST /v1/versions/{id}/revoke   撤销尚未扩散的版本
  POST /v1/nodes/{id}/pull        边缘节点拉取安全更新链
  POST /v1/nodes/{id}/receipts    边缘节点回执（去重/防倒退）
  GET  /v1/nodes                  节点总览
  GET  /v1/nodes/{id}             节点状态与回执日志
  GET  /v1/versions               版本传播总览
  GET  /healthz
"""
from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from service import Service, ServiceError
from storage import Store

STORE: Store | None = None
SERVICE: Service | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "PolicyController/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[controller] {self.address_string()} - {fmt % args}", flush=True)

    # ---- helpers ----
    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as e:
            raise ServiceError("bad_json", f"invalid json: {e}")
        if not isinstance(data, dict):
            raise ServiceError("bad_json", "body must be a JSON object")
        return data

    def _err(self, e: Exception) -> None:
        if isinstance(e, ServiceError):
            self._send_json(e.http_status, {"error": e.code, "message": str(e)})
        else:
            self._send_json(500, {"error": "internal", "message": str(e)})

    # ---- GET ----
    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            if path == "/healthz":
                self._send_json(200, {"ok": True})
            elif path == "/v1/nodes":
                self._send_json(200, {"nodes": SERVICE.nodes_view()})
            elif path == "/v1/versions":
                self._send_json(200, {"versions": SERVICE.versions_view()})
            else:
                m = re.fullmatch(r"/v1/nodes/([^/]+)", path)
                if m:
                    self._send_json(200, SERVICE.node_detail(m.group(1)))
                else:
                    self._send_json(404, {"error": "not_found", "message": path})
        except Exception as e:  # noqa: BLE001
            self._err(e)

    # ---- POST ----
    def do_POST(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            data = self._read_json()

            if path == "/v1/scopes":
                SERVICE.ensure_scope(data["name"], data.get("parent"))
                self._send_json(200, {"scope": data["name"], "parent": data.get("parent")})

            elif path == "/v1/versions":
                result = SERVICE.publish(
                    scope=data["scope"], content=data["content"],
                    deps=data.get("deps"), override=bool(data.get("override", False)),
                    target_regions=data.get("target_regions") or [],
                    target_nodes=data.get("target_nodes") or [],
                    parent_scope=data.get("parent_scope"))
                self._send_json(201, result)

            else:
                m = re.fullmatch(r"/v1/versions/([^/]+)/revoke", path)
                if m:
                    self._send_json(200, SERVICE.revoke(m.group(1)))
                    return
                m = re.fullmatch(r"/v1/nodes/([^/]+)/pull", path)
                if m:
                    node_id = m.group(1)
                    region = data.get("region")
                    if not region:
                        raise ServiceError("bad_region", "region required")
                    present = data.get("present") or {}
                    if not isinstance(present, dict):
                        raise ServiceError("bad_present", "present must be object")
                    self._send_json(200, SERVICE.pull(node_id, region, present))
                    return
                m = re.fullmatch(r"/v1/nodes/([^/]+)/receipts", path)
                if m:
                    node_id = m.group(1)
                    region = data.get("region")
                    if not region:
                        raise ServiceError("bad_region", "region required")
                    for k in ("seq", "version_id", "state"):
                        if k not in data:
                            raise ServiceError("bad_receipt", f"{k} required")
                    self._send_json(200, SERVICE.receipt(
                        node_id, region, int(data["seq"]),
                        data["version_id"], data["state"], data.get("sha256")))
                    return
                self._send_json(404, {"error": "not_found", "message": path})
        except Exception as e:  # noqa: BLE001
            self._err(e)


def main() -> None:
    global STORE, SERVICE
    db_path = os.environ.get("CONTROLLER_DB", "/data/controller.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    secret = os.environ.get("SIGNING_SECRET", "dev-shared-secret")
    host = os.environ.get("CONTROLLER_HOST", "0.0.0.0")
    port = int(os.environ.get("CONTROLLER_PORT", "8080"))
    STORE = Store(db_path)
    SERVICE = Service(STORE, signing_secret=secret)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[controller] listening on {host}:{port}, db={db_path}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
