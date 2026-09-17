#!/usr/bin/env python3
"""Tiny zero-dependency CLI for the control service.

Usage:
  ppcli.py scopes add NAME
  ppcli.py publish SCOPE --file PATH [--kind override --regions eu,us]
                         [--requires a,b]
  ppcli.py revoke VERSION
  ppcli.py versions [SCOPE]
  ppcli.py nodes
  ppcli.py node NODE_ID

Reads PP_URL (default http://localhost:8080).
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error

BASE = os.environ.get("PP_URL", "http://localhost:8080")


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        msg = e.read().decode()
        print(f"error {e.code}: {msg}", file=sys.stderr)
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scopes")
    sp.add_argument("action", choices=["add", "list"])
    sp.add_argument("name", nargs="?")

    pu = sub.add_parser("publish")
    pu.add_argument("scope")
    pu.add_argument("--file", required=True)
    pu.add_argument("--kind", default="base", choices=["base", "override"])
    pu.add_argument("--regions")
    pu.add_argument("--requires")
    pu.add_argument("--parent")

    rv = sub.add_parser("revoke")
    rv.add_argument("version")

    vl = sub.add_parser("versions")
    vl.add_argument("scope", nargs="?")

    sub.add_parser("nodes")

    nd = sub.add_parser("node")
    nd.add_argument("node_id")

    a = ap.parse_args()
    if a.cmd == "scopes" and a.action == "add":
        out = call("POST", "/scopes", {"name": a.name})
    elif a.cmd == "scopes":
        out = call("GET", "/scopes")
    elif a.cmd == "publish":
        with open(a.file, "rb") as f:
            body = {"scope": a.scope, "kind": a.kind,
                    "content_b64": base64.b64encode(f.read()).decode()}
        if a.regions:
            body["regions"] = a.regions.split(",")
        if a.requires:
            body["requires"] = a.requires.split(",")
        if a.parent:
            body["parent"] = a.parent
        out = call("POST", "/versions", body)
    elif a.cmd == "revoke":
        out = call("POST", f"/versions/{a.version}/revoke", {})
    elif a.cmd == "versions":
        out = call("GET", "/versions" + (f"?scope={a.scope}" if a.scope
                                         else ""))
    elif a.cmd == "nodes":
        out = call("GET", "/nodes")
    elif a.cmd == "node":
        out = call("GET", f"/nodes/{a.node_id}")

    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
