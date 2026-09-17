"""SQLite storage. A single connection guarded by a process-wide lock.

The HTTP server is threaded, but the workload is tiny. One connection with
WAL and a serialising lock gives us transactional, crash-safe semantics
without any ORM.
"""
import hashlib
import json
import os
import sqlite3
import threading

_LOCK = threading.RLock()
_CONN = None
_DB_PATH = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS scopes (
    name        TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL
);

-- One config version. kind=base moves the main line forward; kind=override
-- hangs off the current base head and only targets a subset of regions.
CREATE TABLE IF NOT EXISTS versions (
    id           TEXT PRIMARY KEY,
    scope        TEXT NOT NULL REFERENCES scopes(name),
    seq          INTEGER NOT NULL,
    kind         TEXT NOT NULL,
    parent       TEXT,                       -- previous version, same scope
    requires     TEXT NOT NULL DEFAULT '[]', -- json list of version ids, other scopes
    regions      TEXT,                       -- json list; NULL => every region
    content_sha  TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    UNIQUE(scope, seq)
);

CREATE TABLE IF NOT EXISTS nodes (
    node_id    TEXT PRIMARY KEY,
    region     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    seen_at    TEXT NOT NULL
);

-- Per-node per-version delivery state. Present iff the version is (or was)
-- relevant to the node. epoch is the fencing token.
CREATE TABLE IF NOT EXISTS node_versions (
    node_id    TEXT NOT NULL REFERENCES nodes(node_id),
    version_id TEXT NOT NULL REFERENCES versions(id),
    state      TEXT NOT NULL,
    epoch      INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(node_id, version_id)
);

-- Every receipt is retained forever: dedupe by (node, receipt_id) and keep
-- the accept/reject verdict for audit.
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id  TEXT NOT NULL,
    node_id     TEXT NOT NULL,
    version_id  TEXT NOT NULL,
    claimed     TEXT NOT NULL,          -- state the node claimed
    epoch       INTEGER,
    accepted    INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    at          TEXT NOT NULL,
    PRIMARY KEY(node_id, receipt_id)
);
"""


def init_db(path: str | None = None):
    """(Re)open the database. Pass ':memory:' for tests."""
    global _CONN, _DB_PATH
    with _LOCK:
        if _CONN is not None:
            _CONN.close()
        _DB_PATH = path or os.environ.get("PP_DB", "/data/control.db")
        if _DB_PATH != ":memory:":
            os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
        _CONN = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode=WAL")
        _CONN.execute("PRAGMA foreign_keys=ON")
        _CONN.executescript(SCHEMA)
        _CONN.commit()


def conn() -> sqlite3.Connection:
    if _CONN is None:
        init_db()
    return _CONN


def lock():
    return _LOCK


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# ---- tiny row helpers -----------------------------------------------------

def version(version_id: str) -> sqlite3.Row | None:
    return conn().execute(
        "SELECT * FROM versions WHERE id=?", (version_id,)
    ).fetchone()


def node(node_id: str) -> sqlite3.Row | None:
    return conn().execute(
        "SELECT * FROM nodes WHERE node_id=?", (node_id,)
    ).fetchone()


def node_state(node_id: str, version_id: str) -> sqlite3.Row | None:
    return conn().execute(
        "SELECT * FROM node_versions WHERE node_id=? AND version_id=?",
        (node_id, version_id),
    ).fetchone()


def jloads(s):
    return json.loads(s) if s else None
