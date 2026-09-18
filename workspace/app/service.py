"""服务层：把核心领域逻辑接到存储上，负责事务、序号水位、签名。"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Optional

from core import ACTIVATED, REVOKED, RANK, Version, can_revoke, decide_receipt, plan_chain
from storage import Store


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sign(secret: str, content: str) -> str:
    if not secret:
        return ""
    return hmac.new(secret.encode(), content.encode(), hashlib.sha256).hexdigest()


class ServiceError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class Service:
    def __init__(self, store: Store, signing_secret: str = ""):
        self.store = store
        self.secret = signing_secret

    # ---------------- 发布 / 作用域 ----------------
    def ensure_scope(self, name: str, parent: Optional[str] = None) -> None:
        with self.store.lock():
            if parent:
                if self.store.scope_parent(parent) is None and parent not in self.store.all_scopes():
                    # 允许随第一个版本隐式建链：父作用域也自动登记
                    self.store.upsert_scope(parent, None)
            self.store.upsert_scope(name, parent)

    def publish(self, *, scope: str, content: str, deps: dict[str, str] | None = None,
                override: bool = False, target_regions: list[str] | None = None,
                target_nodes: list[str] | None = None,
                parent_scope: str | None = None) -> dict[str, Any]:
        deps = deps or {}
        target_regions = target_regions or []
        target_nodes = target_nodes or []
        if not scope or not isinstance(scope, str):
            raise ServiceError("bad_scope", "scope required")
        if content is None:
            raise ServiceError("bad_content", "content required")
        if override and not target_regions and not target_nodes:
            raise ServiceError("bad_target",
                               "emergency override must target regions or nodes")
        # 覆盖允许临时针对非登记作用域；普通发布必须声明父作用域链
        with self.store.lock():
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                known = self.store.all_scopes()
                if scope not in known:
                    self.store.upsert_scope(scope, parent_scope)
                    known = self.store.all_scopes()

                # 校验依赖：父版本存在、属于祖先作用域、且未撤销
                versions_all = {v.id: v for v in self.store.list_versions()}
                chain = _scope_chain(known, scope)
                for dep_scope, dep_vid in deps.items():
                    if dep_scope not in chain[:-1]:
                        raise ServiceError("bad_dep_scope",
                                           f"{dep_scope} is not an ancestor scope of {scope}")
                    dv = versions_all.get(dep_vid)
                    if dv is None:
                        raise ServiceError("bad_dep_version",
                                           f"dependency {dep_vid} not found")
                    if dv.revoked:
                        raise ServiceError("bad_dep_revoked",
                                           f"dependency {dep_vid} is revoked")

                seq = self.store.next_seq(scope)
                vid = f"{scope}@{seq}"
                v = Version(
                    id=vid, scope=scope, seq=seq, content=content,
                    content_sha256=_sha256(content), signature=_sign(self.secret, content),
                    deps=dict(deps), override=override,
                    target_regions=list(target_regions), target_nodes=list(target_nodes))
                self.store.insert_version(v)
                self.store.conn.execute("COMMIT")
            except Exception:
                self.store.conn.execute("ROLLBACK")
                raise
        return {"version_id": vid, "scope": scope, "seq": seq,
                "content_sha256": v.content_sha256,
                "targeted": override, "revoked": False}

    # ---------------- 撤销 ----------------
    def revoke(self, version_id: str) -> dict[str, Any]:
        with self.store.lock():
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                v = self.store.get_version(version_id)
                if v is None:
                    raise ServiceError("not_found", f"{version_id} not found", 404)
                states = self.store.version_states_across_nodes(version_id)
                ok, reason = can_revoke(v, states)
                if not ok:
                    raise ServiceError("revoke_rejected", reason, 409)
                self.store.mark_revoked(version_id)
                self.store.conn.execute("COMMIT")
            except Exception:
                self.store.conn.execute("ROLLBACK")
                raise
        return {"version_id": version_id, "revoked": True,
                "note": "nodes holding this version receive RECALL on next pull"}

    # ---------------- 节点拉取 ----------------
    def pull(self, node_id: str, region: str,
             present: dict[str, str]) -> dict[str, Any]:
        with self.store.lock():
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                self.store.register_node(node_id, region)
                node = self.store.get_node(node_id)
                hw = int(node["hw_seq"])
                self.store.touch_node(node_id)

                # 用控制端已观测状态与节点上报状态合并，避免错过未回执动作
                observed = self.store.node_states(node_id)
                merged = dict(present)
                merged.update(observed)

                versions = self.store.list_versions()
                plan = plan_chain(versions, node_id, region, merged)

                # 对账：控制端已观测但与节点上报不一致的状态（崩溃恢复 / 漏发级联）。
                # 只推进不回退（REVOKED 例外），节点据此补发幂等回执。
                reconcile: list[dict[str, Any]] = []
                for vid2, obs_st in observed.items():
                    local_st = present.get(vid2)
                    if local_st == obs_st:
                        continue
                    if obs_st == REVOKED or local_st is None or RANK[obs_st] >= RANK.get(local_st, 0):
                        reconcile.append({"version_id": vid2, "state": obs_st})

                ops_payload: list[dict[str, Any]] = []
                for op in plan.ops:
                    if op.type == "RECALL":
                        ops_payload.append({"type": "RECALL",
                                            "version_id": op.version.id,
                                            "reason": op.reason})
                    else:
                        v = op.version
                        ops_payload.append({
                            "type": "APPLY", "version_id": v.id,
                            "scope": v.scope, "seq": v.seq, "content": v.content,
                            "content_sha256": v.content_sha256,
                            "signature": v.signature, "deps": v.deps,
                            "override": v.override, "reason": op.reason})
                self.store.conn.execute("COMMIT")
            except Exception:
                self.store.conn.execute("ROLLBACK")
                raise
        return {"node_id": node_id, "region": region, "high_water": hw,
                "ops": ops_payload, "blocked": plan.blocked,
                "reconcile": reconcile}

    # ---------------- 回执 ----------------
    def receipt(self, node_id: str, region: str, seq: int,
                version_id: str, state: str, sha256: str | None) -> dict[str, Any]:
        with self.store.lock():
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                self.store.register_node(node_id, region)
                self.store.touch_node(node_id)
                node = self.store.get_node(node_id)
                hw = int(node["hw_seq"])

                # 旧序号：必须是“此前已持久化的同一条”才幂等；
                # 与记录不符（或该 seq 从未存在）一律拒绝，且不改任何状态。
                if seq <= hw:
                    prev = self.store.receipt_at(node_id, seq)
                    if prev is not None and prev["version_id"] == version_id \
                            and prev["state"] == state:
                        self.store.conn.execute("COMMIT")
                        return {"accepted": bool(prev["accepted"]),
                                "reason": f"duplicate seq (first verdict: {prev['reason']})",
                                "state": prev["state"], "high_water": hw,
                                "duplicate": True}
                    self.store.conn.execute("COMMIT")
                    return {"accepted": False,
                            "reason": f"stale seq {seq} <= high_water {hw}",
                            "high_water": hw, "duplicate": False}

                # 空洞序号（跳过下一个预期 seq）：拒绝且不落库、不推进水位。
                # 乱序/重影绝不能污染回执日志，否则合法补发会被误判为倒退。
                if seq != hw + 1:
                    self.store.conn.execute("COMMIT")
                    return {"accepted": False,
                            "reason": f"gap: expected seq={hw + 1}, got {seq}",
                            "high_water": hw, "duplicate": False}

                versions = {v.id: v for v in self.store.list_versions()}
                node_states = self.store.node_states(node_id)
                active_by_scope: dict[str, list[str]] = {}
                for vid2 in node_states:
                    if node_states[vid2] == ACTIVATED and vid2 in versions:
                        active_by_scope.setdefault(versions[vid2].scope, []).append(vid2)
                last = self.store.last_receipt(node_id)

                decision = decide_receipt(
                    claimed_version_id=version_id, claimed_state=state, seq=seq,
                    sha256=sha256, high_water=hw,
                    last_seq=int(last["seq"]) if last else None,
                    last_version_id=last["version_id"] if last else None,
                    last_state=last["state"] if last else None,
                    node_states=node_states, versions=versions,
                    active_versions_by_scope=active_by_scope)

                if decision.accepted and decision.new_state:
                    self.store.upsert_node_version(node_id, version_id, decision.new_state)
                    for other_id, other_state in decision.cascades:
                        self.store.upsert_node_version(node_id, other_id, other_state)

                # 只有恰为下一个序号的回执落库并推进水位；
                # 确定性拒绝（如错误哈希）也落库——拒绝结论是确定事实，
                # 节点随后发下一个 seq 即可继续，旧结论不可重放。
                self.store.set_hw(node_id, seq)
                self.store.insert_receipt(node_id, seq, version_id, state,
                                          decision.accepted, decision.reason)
                self.store.conn.execute("COMMIT")
            except Exception:
                self.store.conn.execute("ROLLBACK")
                raise
        return {"accepted": decision.accepted, "reason": decision.reason,
                "state": decision.new_state or state, "high_water": seq,
                "duplicate": False}

    # ---------------- 视图 ----------------
    def nodes_view(self) -> list[dict[str, Any]]:
        out = []
        for n in self.store.list_nodes():
            out.append({"id": n["id"], "region": n["region"],
                        "high_water": int(n["hw_seq"]),
                        "last_seen": n["last_seen_at"],
                        "registered_at": n["registered_at"]})
        return out

    def versions_view(self) -> list[dict[str, Any]]:
        rows = self.store.propagation_rows()
        versions: dict[str, dict[str, Any]] = {}
        for r in rows:
            vid = r["version_id"]
            agg = versions.setdefault(vid, {
                "version_id": vid, "scope": r["scope"], "seq": r["seq"],
                "revoked": bool(r["revoked"]), "override": bool(r["override"]),
                "states": {}})
            if r["node_id"]:
                agg["states"].setdefault(r["state"], []).append(
                    {"node": r["node_id"], "region": r["region"]})
        return list(versions.values())

    def node_detail(self, node_id: str) -> dict[str, Any]:
        node = self.store.get_node(node_id)
        if node is None:
            raise ServiceError("not_found", f"node {node_id} not found", 404)
        receipts = [dict(r) for r in self.store.list_receipts(node_id)]
        return {"id": node_id, "region": node["region"],
                "high_water": int(node["hw_seq"]),
                "last_seen": node["last_seen_at"],
                "states": self.store.node_states(node_id),
                "receipts": receipts}


def _scope_chain(known: dict[str, Optional[str]], scope: str) -> list[str]:
    """返回从根到 scope 的作用域链（含自身）；有环/断裂则抛错。"""
    chain: list[str] = []
    cur: Optional[str] = scope
    seen: set[str] = set()
    while cur is not None:
        if cur in seen:
            raise ServiceError("scope_cycle", f"scope cycle at {cur}")
        seen.add(cur)
        chain.append(cur)
        cur = known.get(cur)
    chain.reverse()
    return chain
