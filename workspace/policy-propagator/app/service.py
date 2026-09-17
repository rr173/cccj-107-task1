"""Core control-plane logic: publish / revoke / poll / receipt.

All rules live here so the HTTP layer is a thin shell and the whole state
machine can be unit-tested in-process against an in-memory SQLite database.
"""
import base64
import json
import uuid
from datetime import datetime, timezone

from . import db
from .states import STATE_RANK, RANK_STATE, ARRIVED_STATES, VALID_KINDS


class DomainError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rowdict(row):
    return dict(row) if row is not None else None


def _jloads(s):
    return json.loads(s) if s else None


# ---------------------------------------------------------------- nodes ---

def register_node(node_id: str, region: str) -> dict:
    with db.lock():
        c = db.conn()
        existing = db.node(node_id)
        if existing:
            c.execute("UPDATE nodes SET seen_at=? WHERE node_id=?",
                      (now(), node_id))
            c.commit()
            d = _rowdict(existing)
            d["seen_at"] = now()
            return d
        c.execute(
            "INSERT INTO nodes(node_id, region, created_at, seen_at)"
            " VALUES(?,?,?,?)",
            (node_id, region, now(), now()),
        )
        c.commit()
        return _rowdict(db.node(node_id))


# -------------------------------------------------------------- publish ---

def _scope_head(c, scope: str, kind: str):
    return c.execute(
        "SELECT * FROM versions WHERE scope=? AND kind=? AND revoked=0"
        " ORDER BY seq DESC LIMIT 1",
        (scope, kind),
    ).fetchone()


def publish(payload: dict) -> dict:
    scope = payload.get("scope")
    kind = payload.get("kind", "base")
    requires = payload.get("requires") or []
    regions = payload.get("regions", None)
    parent_override = payload.get("parent")
    content_b64 = payload.get("content_b64", "")

    if not scope or not isinstance(scope, str):
        raise DomainError("scope is required")
    if kind not in VALID_KINDS:
        raise DomainError(f"kind must be one of {VALID_KINDS}")
    try:
        content = base64.b64decode(content_b64.encode(), validate=True)
    except Exception:
        raise DomainError("content_b64 must be valid base64")
    if not content:
        raise DomainError("content must not be empty")

    if kind == "override":
        if not isinstance(regions, list) or not regions:
            raise DomainError("override requires a non-empty regions list")
    else:
        if regions is not None:
            raise DomainError("base versions cannot carry region filters")

    with db.lock():
        c = db.conn()
        c.execute("INSERT OR IGNORE INTO scopes(name, created_at) VALUES(?,?)",
                  (scope, now()))

        base_head = _scope_head(c, scope, "base")
        if kind == "base":
            expected_parent = base_head["id"] if base_head else None
            parent = parent_override or expected_parent
            if parent != expected_parent:
                raise DomainError(
                    f"non-linear base append: parent must be current head "
                    f"{expected_parent!r}", status=409)
        else:
            # An emergency override is forked off the current main-line head.
            if base_head is None:
                raise DomainError("cannot override a scope with no base version")
            parent = parent_override or base_head["id"]
            if parent != base_head["id"]:
                raise DomainError(
                    "override parent must be the current base head", status=409)

        pv = None
        if parent is not None:
            pv = db.version(parent)
            if pv is None:
                raise DomainError("parent version does not exist")
            if pv["scope"] != scope:
                raise DomainError("parent must belong to the same scope")
            if pv["revoked"]:
                raise DomainError("cannot build on a revoked parent", status=409)

        seen_req = set()
        for r in requires:
            if not isinstance(r, str):
                raise DomainError("requires must be version id strings")
            if r in seen_req:
                raise DomainError(f"duplicate requires entry {r}")
            seen_req.add(r)
            rv = db.version(r)
            if rv is None:
                raise DomainError(f"requires unknown version {r}")
            if rv["revoked"]:
                raise DomainError(f"requires revoked version {r}", status=409)
            if rv["scope"] == scope:
                raise DomainError(
                    "same-scope ordering uses parent; requires is cross-scope")

        seqrow = c.execute(
            "SELECT COALESCE(MAX(seq),0)+1 AS s FROM versions WHERE scope=?",
            (scope,)).fetchone()
        seq = seqrow["s"]
        vid = f"{scope}-v{seq}"
        sha = db.digest(content)
        c.execute(
            "INSERT INTO versions(id,scope,seq,kind,parent,requires,regions,"
            "content_sha,size_bytes,revoked,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,0,?)",
            (vid, scope, seq, kind, parent, json.dumps(requires),
             json.dumps(regions) if regions is not None else None,
             sha, len(content), now()),
        )
        # Blob content lives on disk next to the DB, addressed by version id.
        with open(_blob_path(vid), "wb") as f:
            f.write(content)
        c.commit()
        return _publish_view(_rowdict(db.version(vid)))


def _publish_view(v: dict) -> dict:
    v["requires"] = _jloads(v["requires"]) or []
    v["regions"] = _jloads(v["regions"])
    return v


def _blob_path(vid: str) -> str:
    import os
    base = os.environ.get("PP_BLOB_DIR", "/data/blobs")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, vid)


def blob_bytes(vid: str) -> bytes:
    v = db.version(vid)
    if v is None or v["revoked"]:
        raise DomainError("unknown or revoked version", status=404)
    with open(_blob_path(vid), "rb") as f:
        return f.read()


# --------------------------------------------------------------- revoke ---

def revoke(version_id: str) -> dict:
    """Recall a version that has not finished spreading.

    Allowed iff no node has ever activated it and no live version is built on
    top of it — otherwise the dependency chain would develop a hole.
    """
    with db.lock():
        c = db.conn()
        v = db.version(version_id)
        if v is None:
            raise DomainError("unknown version", status=404)
        if v["revoked"]:
            raise DomainError("already revoked", status=409)

        activated = c.execute(
            "SELECT node_id FROM node_versions WHERE version_id=?"
            " AND state IN ('ACTIVATED','OVERRIDDEN')",
            (version_id,)).fetchall()
        if activated:
            raise DomainError(
                f"cannot revoke: already active on "
                f"{sorted(r['node_id'] for r in activated)}; publish a"
                " successor instead", status=409)

        descendants = c.execute(
            "SELECT id FROM versions WHERE revoked=0 AND (parent=? OR "
            "requires LIKE ?)",
            (version_id, f'%"{version_id}"%')).fetchall()
        if descendants:
            raise DomainError(
                f"cannot revoke: live descendants "
                f"{sorted(r['id'] for r in descendants)} depend on it",
                status=409)

        c.execute("UPDATE versions SET revoked=1 WHERE id=?", (version_id,))
        # Every in-flight copy is invalidated. The state goes to PURGED and
        # the epoch advances so any late pre-revoke receipt is fenced off.
        affected = c.execute(
            "UPDATE node_versions SET state='PURGED', epoch=epoch+1,"
            " updated_at=? WHERE version_id=? AND state IN "
            "('PENDING','DOWNLOADED','VERIFIED')",
            (now(), version_id))
        c.commit()
        return {"id": version_id, "revoked": True,
                "inflight_nodes_invalidated": affected.rowcount}


# ----------------------------------------------------------------- poll ---

def _desired_for_region(c, scope: str, region: str):
    """Pick the applicable version for one scope at one region.

    A live emergency override for the region beats the main line; it stays in
    force until a newer override for that region supersedes it.
    """
    rows = c.execute(
        "SELECT * FROM versions WHERE scope=? AND revoked=0"
        " ORDER BY seq DESC", (scope,)).fetchall()
    base = None
    override = None
    for r in rows:
        regs = _jloads(r["regions"])
        if r["kind"] == "base":
            if base is None:
                base = r
        elif regs and region in regs and override is None:
            override = r
    return override or base


def _has_newer_active_sibling(c, node_id, scope, vid) -> bool:
    return c.execute(
        "SELECT 1 FROM node_versions nv JOIN versions w ON w.id=nv.version_id"
        " WHERE nv.node_id=? AND w.scope=? AND nv.state='ACTIVATED'"
        " AND w.id<>? LIMIT 1", (node_id, scope, vid)).fetchone() is not None


def _ensure_row(c, node_id, vid, state, epoch):
    c.execute(
        "INSERT INTO node_versions(node_id,version_id,state,epoch,updated_at)"
        " VALUES(?,?,?,?,?)"
        " ON CONFLICT(node_id,version_id) DO UPDATE SET state=excluded.state,"
        " epoch=excluded.epoch, updated_at=excluded.updated_at",
        (node_id, vid, state, epoch, now()))


def poll(node_id: str, report: dict) -> dict:
    n = db.node(node_id)
    if n is None:
        raise DomainError("unknown node; register first", status=404)
    region = n["region"]
    reported = {}
    for item in report.get("versions", []):
        vid, st = item.get("version"), item.get("state")
        if not vid or st not in STATE_RANK:
            raise DomainError(f"bad report entry {item!r}")
        reported[vid] = st
    active_claim = report.get("active", {}) or {}
    if not isinstance(active_claim, dict):
        raise DomainError("active must be {scope: version_id}")

    with db.lock():
        c = db.conn()
        c.execute("UPDATE nodes SET seen_at=? WHERE node_id=?",
                  (now(), node_id))

        # 1) reconcile the node's self-report against control truth --------
        for vid, st in reported.items():
            if db.version(vid) is None:
                raise DomainError(f"report for unknown version {vid}", 409)
            rv = db.node_state(node_id, vid)
            if rv is None:
                # Node has bytes the control never formally targeted it at:
                # adopt the claim with a fresh fence.
                _ensure_row(c, node_id, vid, st, 1)
                continue
            cur_rank = STATE_RANK[rv["state"]]
            new_rank = STATE_RANK[st]
            if rv["state"] == "PURGED":
                continue  # sticky; purge list below drives the node
            if st == "OVERRIDDEN" and not _has_newer_active_sibling(
                    c, node_id, db.version(vid)["scope"], vid):
                # a node cannot retire a version by itself; only activation
                # of a newer sibling (server-driven) earns OVERRIDDEN.
                continue
            if new_rank > cur_rank:
                _ensure_row(c, node_id, vid, st, rv["epoch"])
            elif new_rank < cur_rank:
                # Control was ahead (e.g. receipt arrived before this poll
                # snapshot): keep control truth.
                pass
            # rank==3..4 terminal: keep control truth
            # For rank<3 where node fell behind control, nothing to do; but a
            # node losing local state below control rank<3 re-arms delivery:
            if cur_rank < STATE_RANK["ACTIVATED"] and new_rank < cur_rank:
                c.execute(
                    "UPDATE node_versions SET state='PENDING', epoch=epoch+1,"
                    " updated_at=? WHERE node_id=? AND version_id=?",
                    (now(), node_id, vid))

        # rows the node previously reported progress on (DOWNLOADED or
        # VERIFIED) but no longer mentions: local copy was lost, re-arm with
        # a fresh fence. Plain PENDING intents are left alone — the node just
        # has not fetched them yet, and bumping their epoch every poll would
        # fence perfectly valid plans.
        for r in c.execute(
                "SELECT version_id,state FROM node_versions WHERE node_id=?",
                (node_id,)).fetchall():
            if r["version_id"] not in reported and r["state"] in (
                    "DOWNLOADED", "VERIFIED"):
                c.execute(
                    "UPDATE node_versions SET state='PENDING', epoch=epoch+1,"
                    " updated_at=? WHERE node_id=? AND version_id=?",
                    (now(), node_id, r["version_id"]))

        # active frontier, from control truth post-reconcile
        active_map = {}
        for r in c.execute(
                "SELECT v.scope AS scope, nv.version_id AS vid FROM"
                " node_versions nv JOIN versions v ON v.id=nv.version_id"
                " WHERE nv.node_id=? AND nv.state='ACTIVATED'",
                (node_id,)).fetchall():
            active_map[r["scope"]] = r["vid"]
        for scope, vid in active_claim.items():
            if scope not in active_map and db.node_state(node_id, vid) \
                    and db.node_state(node_id, vid)["state"] == "ACTIVATED":
                vv = db.version(vid)
                if vv and vv["scope"] == scope:
                    active_map[scope] = vid

        # 2) desired version per scope, then safe ancestor chains ----------
        desired = {}
        for srow in c.execute("SELECT name FROM scopes").fetchall():
            d = _desired_for_region(c, srow["name"], region)
            if d is not None:
                desired[srow["name"]] = d["id"]

        needed, errors = _build_needed(c, node_id, active_map, desired)
        if errors:
            c.commit()
            raise DomainError("; ".join(errors), status=409)

        # 3) materialise intents, plan + purge lists -----------------------
        for vid in needed:
            if db.node_state(node_id, vid) is None:
                _ensure_row(c, node_id, vid, "PENDING", 1)

        c.commit()

        plan = []
        for vid in _topo_order(c, needed):
            rv = db.node_state(node_id, vid)
            if rv["state"] == "PENDING":
                v = db.version(vid)
                plan.append({
                    "version": vid, "scope": v["scope"], "seq": v["seq"],
                    "kind": v["kind"], "parent": v["parent"],
                    "requires": _jloads(v["requires"]) or [],
                    "content_sha": v["content_sha"],
                    "size_bytes": v["size_bytes"],
                    "blob_url": f"/blobs/{vid}", "epoch": rv["epoch"],
                })

        purge, current = [], {}
        for r in c.execute(
                "SELECT nv.version_id AS vid, nv.state AS state, nv.epoch AS e"
                " FROM node_versions nv WHERE nv.node_id=?",
                (node_id,)).fetchall():
            current[r["vid"]] = {"state": r["state"], "epoch": r["e"]}
            if r["state"] == "PURGED" and reported.get(r["vid"]) != "PURGED":
                purge.append({"version": r["vid"], "epoch": r["e"]})

        return {"desired": desired, "plan": plan, "purge": purge,
                "current": current, "errors": []}


def _walk_scope_chain(c, node_id, desired_id, baseline):
    """Walk same-scope ancestors until something that already arrived.

    Returns (versions, error). Every version between the local baseline and
    the desired version is included in order, so a long-offline node gets a
    safe chain instead of the newest snapshot. An override replacing another
    override is a self-contained jump, but its base parents between the two
    fork points still have to be applied (the activation gate requires them).
    """
    out, seen, cur, reached = [], set(), desired_id, False
    while cur:
        if cur in seen:
            return out, f"parent cycle at {cur}"
        seen.add(cur)
        v = db.version(cur)
        if v is None:
            return out, f"missing version {cur}"
        if v["revoked"]:
            return out, f"chain passes revoked version {cur}"
        nr = db.node_state(node_id, cur)
        if nr and nr["state"] in ARRIVED_STATES:
            reached = True
            break
        out.append(cur)
        if baseline and cur == baseline:
            reached = True
            break
        cur = v["parent"]

    if baseline and not reached:
        dv = db.version(desired_id)
        bv = db.version(baseline)
        if dv["kind"] == "base" and bv["kind"] == "base":
            return out, (f"local baseline {baseline} is not an ancestor"
                         f" of {desired_id}; cannot safely advance")
        # override replacing override / main line: full ancestor chain is a
        # safe self-contained update path
    return out, None


def _build_needed(c, node_id, active_map, desired):
    needed, errors = set(), []
    for scope, did in desired.items():
        baseline = active_map.get(scope)
        if baseline == did:
            continue
        if baseline:
            bv = db.version(baseline)
            if bv is None or bv["revoked"]:
                errors.append(f"active {baseline} in {scope} is gone")
                continue
        chain, err = _walk_scope_chain(c, node_id, did, baseline)
        if err:
            errors.append(err)
        needed.update(chain)

    # cross-scope requires, recursively, each with its own ancestor chain
    stack = list(needed)
    while stack:
        vid = stack.pop()
        v = db.version(vid)
        for r in (_jloads(v["requires"]) or []):
            rr = db.node_state(node_id, r)
            if rr and rr["state"] in ARRIVED_STATES:
                continue
            rv = db.version(r)
            if rv is None or rv["revoked"]:
                errors.append(f"dependency {r} missing or revoked")
                continue
            cur, seen = r, set()
            while cur:
                if cur in seen:
                    errors.append(f"parent cycle at {cur}")
                    break
                seen.add(cur)
                cv = db.version(cur)
                if cv is None or cv["revoked"]:
                    errors.append(f"dependency chain broken at {cur}")
                    break
                ar = db.node_state(node_id, cur)
                if ar and ar["state"] in ARRIVED_STATES:
                    break
                if cur not in needed:
                    needed.add(cur)
                    stack.append(cur)
                cur = cv["parent"]
    return needed, sorted(set(errors))


def _topo_order(c, needed):
    """Order by (parent then requires), deterministic by (seq, id)."""
    order, done, visiting = [], set(), set()

    def visit(vid):
        if vid in done:
            return
        if vid in visiting:
            raise DomainError(f"dependency cycle involving {vid}", 409)
        visiting.add(vid)
        v = db.version(vid)
        if v["parent"] and v["parent"] in needed:
            visit(v["parent"])
        for r in (_jloads(v["requires"]) or []):
            if r in needed:
                visit(r)
        visiting.discard(vid)
        done.add(vid)
        order.append(vid)

    for vid in sorted(needed, key=lambda x: (db.version(x)["seq"], x)):
        visit(vid)
    return order


# -------------------------------------------------------------- receipt ---

def receipt(node_id: str, p: dict) -> dict:
    rid = p.get("receipt_id")
    vid = p.get("version")
    claimed = p.get("state")
    epoch = p.get("epoch")
    content_sha = p.get("content_sha")

    if not rid:
        raise DomainError("receipt_id required")
    if claimed not in STATE_RANK:
        raise DomainError(f"unknown claimed state {claimed!r}")

    with db.lock():
        c = db.conn()
        if db.node(node_id) is None:
            raise DomainError("unknown node", 404)
        dup = c.execute(
            "SELECT * FROM receipts WHERE node_id=? AND receipt_id=?",
            (node_id, rid)).fetchone()
        if dup is not None:
            # duplicate delivery: replay the original verdict, never re-apply
            return {"accepted": bool(dup["accepted"]),
                    "duplicate": True, "reason": dup["reason"],
                    "state": db.node_state(node_id, vid)["state"]
                    if db.node_state(node_id, vid) else None}

        def record(ok, reason):
            c.execute(
                "INSERT INTO receipts(receipt_id,node_id,version_id,claimed,"
                "epoch,accepted,reason,at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, node_id, vid, claimed, epoch, 1 if ok else 0,
                 reason, now()))
            c.commit()
            return {"accepted": ok, "reason": reason,
                    "state": db.node_state(node_id, vid)["state"]
                    if db.node_state(node_id, vid) else None}

        v = db.version(vid) if vid else None
        if v is None:
            return record(False, "unknown version")
        rv = db.node_state(node_id, vid)
        if rv is None:
            return record(False, "version never targeted at this node")

        cur, target = rv["state"], STATE_RANK[claimed]
        cur_rank = STATE_RANK[cur]

        if claimed == cur:
            # A PURGED ack must carry the current revoke epoch even though it
            # is a same-state ack; otherwise it is a stale retransmit.
            if claimed == "PURGED" and epoch != rv["epoch"]:
                return record(False, "stale epoch (fenced by revoke)")
            return record(True, "idempotent same-state ack")
        if cur == "PURGED":
            return record(False, "version revoked; purge required")
        if target < cur_rank:
            return record(False,
                          f"stale receipt: {claimed} cannot move {cur}"
                          " backwards")
        # PURGED is a server-driven outcome of revoke
        if claimed == "PURGED":
            if not v["revoked"]:
                return record(False, "PURGED only valid after control revoke")
            if epoch != rv["epoch"]:
                return record(False, "stale epoch (fenced by revoke)")
            return record(True, "purge acknowledged")
        if epoch != rv["epoch"]:
            return record(False,
                          f"stale epoch {epoch}!={rv['epoch']} (fenced)")
        if target != cur_rank + 1:
            need = RANK_STATE.get(cur_rank + 1)
            return record(False,
                          f"out of order: {need} must be reported before"
                          f" {claimed}")
        if claimed == "DOWNLOADED" and not content_sha:
            return record(False, "DOWNLOADED receipt needs content_sha claim")
        if claimed == "VERIFIED" and content_sha != v["content_sha"]:
            return record(False,
                          f"hash mismatch: {content_sha} != {v['content_sha']}")
        if claimed == "ACTIVATED":
            gate = _activation_gate(c, node_id, v)
            if gate:
                return record(False, gate)
        if claimed == "OVERRIDDEN":
            if not _has_newer_active_sibling(c, node_id, v["scope"], vid):
                return record(False, "no newer active sibling to override it")

        c.execute(
            "UPDATE node_versions SET state=?, updated_at=?"
            " WHERE node_id=? AND version_id=?",
            (claimed, now(), node_id, vid))

        if claimed == "ACTIVATED":
            # server-side override of the previous active version in scope;
            # epoch bump fences its late ACTIVATED receipts.
            c.execute(
                "UPDATE node_versions SET state='OVERRIDDEN', epoch=epoch+1,"
                " updated_at=? WHERE node_id=? AND state='ACTIVATED' AND"
                " version_id IN (SELECT id FROM versions WHERE scope=? AND"
                " id<>?)",
                (now(), node_id, v["scope"], vid))
        c.commit()
        return record(True, f"advanced to {claimed}")


def _activation_gate(c, node_id, v) -> str | None:
    """Return a rejection reason if the dependency gate is not satisfied."""
    deps = [v["parent"]] if v["parent"] else []
    deps += _jloads(v["requires"]) or []
    for d in deps:
        dr = db.node_state(node_id, d)
        if dr is None:
            return f"gate closed: dependency {d} never delivered"
        if dr["state"] not in ARRIVED_STATES:
            return f"gate closed: dependency {d} is {dr['state']}"
    return None


# ------------------------------------------------------------- queries ---

def list_scopes() -> list:
    return [_rowdict(r) for r in db.conn()
            .execute("SELECT * FROM scopes ORDER BY name").fetchall()]


def list_versions(scope: str | None = None) -> list:
    q = "SELECT * FROM versions"
    args = ()
    if scope:
        q += " WHERE scope=?"
        args = (scope,)
    q += " ORDER BY scope, seq"
    out = []
    for r in db.conn().execute(q, args).fetchall():
        out.append(_publish_view(_rowdict(r)))
    return out


def get_version(vid: str) -> dict:
    v = db.version(vid)
    if v is None:
        raise DomainError("unknown version", 404)
    return _publish_view(_rowdict(v))


def list_nodes() -> list:
    return [_node_view(r["node_id"]) for r in db.conn()
            .execute("SELECT node_id FROM nodes ORDER BY node_id").fetchall()]


def get_node(node_id: str) -> dict:
    if db.node(node_id) is None:
        raise DomainError("unknown node", 404)
    return _node_view(node_id)


def _node_view(node_id: str) -> dict:
    n = _rowdict(db.node(node_id))
    n["versions"] = []
    for r in db.conn().execute(
            "SELECT nv.version_id AS vid, nv.state AS state, nv.epoch AS epoch,"
            " v.scope AS scope FROM node_versions nv JOIN versions v ON"
            " v.id=nv.version_id WHERE nv.node_id=?"
            " ORDER BY v.scope, v.seq", (node_id,)).fetchall():
        n["versions"].append({"version": r["vid"], "scope": r["scope"],
                              "state": r["state"], "epoch": r["epoch"]})
    return n
