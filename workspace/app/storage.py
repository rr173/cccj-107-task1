"""SQLite 持久层：版本、作用域、节点、节点版本状态、回执日志。

所有写操作在 service 层显式事务里执行；存储层只负责 SQL 与行映射。
"""
from __future__ import annotations

import sqlite3
import threading
from typing import Any, Optional

from core import Version

SCHEMA = """
CREATE TABLE IF NOT EXISTS scopes (
    name       TEXT PRIMARY KEY,
    parent     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS versions (
    id             TEXT PRIMARY KEY,
    scope          TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    content        TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    signature      TEXT NOT NULL DEFAULT '',
    deps           TEXT NOT NULL DEFAULT '{}',
    override       INTEGER NOT NULL DEFAULT 0,
    target_regions TEXT NOT NULL DEFAULT '[]',
    target_nodes   TEXT NOT NULL DEFAULT '[]',
    revoked        INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scope, seq)
);
CREATE TABLE IF NOT EXISTS nodes (
    id           TEXT PRIMARY KEY,
    region       TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT,
    hw_seq       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS node_versions (
    node_id    TEXT NOT NULL,
    version_id TEXT NOT NULL,
    state      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (node_id, version_id),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
);
CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    version_id  TEXT NOT NULL,
    state       TEXT NOT NULL,
    accepted    INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    seen_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(node_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_nv_state ON node_versions(version_id, state);
"""


class Store:
    def __init__(self, path: str):
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.conn.executescript(SCHEMA)

    def lock(self) -> threading.RLock:
        return self._lock

    # ---- 作用域 / 版本 ----
    def upsert_scope(self, name: str, parent: Optional[str]) -> None:
        self.conn.execute(
            "INSERT INTO scopes(name, parent) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET parent=COALESCE(excluded.parent, parent)",
            (name, parent))

    def scope_parent(self, name: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT parent FROM scopes WHERE name=?", (name,)).fetchone()
        return row["parent"] if row else None

    def all_scopes(self) -> dict[str, Optional[str]]:
        return {r["name"]: r["parent"]
                for r in self.conn.execute("SELECT name, parent FROM scopes")}

    def insert_version(self, v: Version) -> None:
        import json
        self.conn.execute(
            "INSERT INTO versions(id, scope, seq, content, content_sha256, signature,"
            " deps, override, target_regions, target_nodes, revoked)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (v.id, v.scope, v.seq, v.content, v.content_sha256, v.signature,
             json.dumps(v.deps), int(v.override),
             json.dumps(v.target_regions), json.dumps(v.target_nodes),
             int(v.revoked)))

    def next_seq(self, scope: str) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM versions WHERE scope=?",
            (scope,)).fetchone()
        return int(row["n"])

    def get_version(self, version_id: str) -> Optional[Version]:
        rows = self.conn.execute(
            "SELECT * FROM versions WHERE id=?", (version_id,)).fetchall()
        return _row_to_version(rows[0]) if rows else None

    def list_versions(self, include_revoked: bool = True) -> list[Version]:
        sql = "SELECT * FROM versions"
        if not include_revoked:
            sql += " WHERE revoked=0"
        sql += " ORDER BY scope, seq"
        return [_row_to_version(r) for r in self.conn.execute(sql)]

    def mark_revoked(self, version_id: str) -> None:
        self.conn.execute(
            "UPDATE versions SET revoked=1 WHERE id=?", (version_id,))

    # ---- 节点 ----
    def register_node(self, node_id: str, region: str) -> None:
        self.conn.execute(
            "INSERT INTO nodes(id, region) VALUES (?, ?) "
            "ON CONFLICT(id) DO NOTHING", (node_id, region))

    def get_node(self, node_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()

    def touch_node(self, node_id: str) -> None:
        self.conn.execute(
            "UPDATE nodes SET last_seen_at=datetime('now') WHERE id=?", (node_id,))

    def set_hw(self, node_id: str, hw: int) -> None:
        self.conn.execute("UPDATE nodes SET hw_seq=? WHERE id=?", (hw, node_id))

    def list_nodes(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM nodes ORDER BY region, id"))

    # ---- 节点版本状态 ----
    def node_states(self, node_id: str) -> dict[str, str]:
        return {r["version_id"]: r["state"] for r in self.conn.execute(
            "SELECT version_id, state FROM node_versions WHERE node_id=?",
            (node_id,))}

    def version_states_across_nodes(self, version_id: str) -> dict[str, str]:
        return {r["node_id"]: r["state"] for r in self.conn.execute(
            "SELECT node_id, state FROM node_versions WHERE version_id=?",
            (version_id,))}

    def active_versions(self, node_id: str, scope: str) -> list[str]:
        return [r["version_id"] for r in self.conn.execute(
            "SELECT nv.version_id FROM node_versions nv JOIN versions v "
            "ON v.id=nv.version_id WHERE nv.node_id=? AND v.scope=? "
            "AND nv.state='ACTIVATED' ORDER BY v.seq", (node_id, scope))]

    def upsert_node_version(self, node_id: str, version_id: str, state: str) -> None:
        self.conn.execute(
            "INSERT INTO node_versions(node_id, version_id, state) VALUES (?,?,?) "
            "ON CONFLICT(node_id, version_id) DO UPDATE SET state=excluded.state, "
            "updated_at=datetime('now')", (node_id, version_id, state))

    # ---- 回执 ----
    def last_receipt(self, node_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM receipts WHERE node_id=? ORDER BY seq DESC LIMIT 1",
            (node_id,)).fetchone()

    def receipt_at(self, node_id: str, seq: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM receipts WHERE node_id=? AND seq=?",
            (node_id, seq)).fetchone()

    def insert_receipt(self, node_id: str, seq: int, version_id: str,
                       state: str, accepted: bool, reason: str) -> None:
        self.conn.execute(
            "INSERT INTO receipts(node_id, seq, version_id, state, accepted, reason)"
            " VALUES (?,?,?,?,?,?)",
            (node_id, seq, version_id, state, int(accepted), reason))

    def list_receipts(self, node_id: str, limit: int = 50) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM receipts WHERE node_id=? ORDER BY seq DESC LIMIT ?",
            (node_id, limit)))

    # ---- 管理视图 ----
    def propagation_rows(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT v.id AS version_id, v.scope, v.seq, v.revoked, v.override,"
            "       nv.node_id, n.region, nv.state "
            "FROM versions v "
            "LEFT JOIN node_versions nv ON nv.version_id=v.id "
            "LEFT JOIN nodes n ON n.id=nv.node_id "
            "ORDER BY v.scope, v.seq, n.region, nv.node_id").fetchall()
        return [dict(r) for r in rows]


def _row_to_version(r: sqlite3.Row) -> Version:
    import json
    return Version(
        id=r["id"], scope=r["scope"], seq=int(r["seq"]),
        content=r["content"], content_sha256=r["content_sha256"],
        signature=r["signature"], deps=json.loads(r["deps"]),
        override=bool(r["override"]),
        target_regions=json.loads(r["target_regions"]),
        target_nodes=json.loads(r["target_nodes"]),
        revoked=bool(r["revoked"]))
