"""策略传播控制面 —— 核心领域逻辑（纯函数，无 IO，便于单测）。

状态机与关键不变量：
  DOWNLOADED -> VERIFIED -> ACTIVATED -> (SUPERSEDED | REPLACED | REVOKED)
  1. 回执按节点单调序号 (seq) 投递；旧序号一律拒绝，防止进度倒退。
  2. ACTIVATED 要求版本依赖的父版本在该节点也已 ACTIVATED。
  3. OVERRIDE 版本在目标节点激活后，该作用域原激活版本 -> SUPERSEDED；
     普通新版本激活时，旧激活版本 -> REPLACED。
  4. 已被任何节点激活的版本不可撤销（只能靠新版本/覆盖纠正）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---- 节点侧版本状态 ---------------------------------------------------------
DOWNLOADED = "DOWNLOADED"
VERIFIED = "VERIFIED"
ACTIVATED = "ACTIVATED"
SUPERSEDED = "SUPERSEDED"   # 被紧急覆盖顶掉
REPLACED = "REPLACED"       # 被同作用域普通新版本替换
REVOKED = "REVOKED"         # 版本被撤销

# 进度只能向前：秩用于检测倒退
RANK = {
    DOWNLOADED: 1,
    VERIFIED: 2,
    ACTIVATED: 3,
    SUPERSEDED: 4,
    REPLACED: 4,
    REVOKED: 4,
}
# 终态：不能再变回活态
TERMINAL = {SUPERSEDED, REPLACED, REVOKED}
# 可向前推进的活态（用于规划链时寻找起点）
LIVE = {DOWNLOADED, VERIFIED, ACTIVATED}

# ---- 链上操作类型 -----------------------------------------------------------
APPLY = "APPLY"   # 下载/校验/激活该版本
RECALL = "RECALL"  # 丢弃本地持有的已撤销版本


@dataclass
class Version:
    id: str                       # 形如 "policy@2"
    scope: str                    # 作用域名
    seq: int                      # 作用域内单调版本号
    content: str                  # 配置内容（字符串）
    content_sha256: str
    signature: str = ""           # HMAC-SHA256(secret, content)
    deps: dict[str, str] = field(default_factory=dict)   # {scope: version_id}
    override: bool = False
    target_regions: list[str] = field(default_factory=list)
    target_nodes: list[str] = field(default_factory=list)
    revoked: bool = False

    def targets(self, node_id: str, node_region: str) -> bool:
        """该版本是否定向到给定节点。普通版本广播，覆盖版本只命中目标。"""
        if not self.override:
            return True
        return node_id in self.target_nodes or node_region in self.target_regions


@dataclass
class ChainOp:
    type: str                     # APPLY / RECALL
    version: Version
    reason: str = ""


@dataclass
class PlanResult:
    ops: list[ChainOp]
    blocked: list[dict] = field(default_factory=list)  # 依赖未就绪的版本


def _seq_of(version_id: str) -> int:
    return int(version_id.rsplit("@", 1)[1])


def plan_chain(
    versions: list[Version],
    node_id: str,
    node_region: str,
    present: dict[str, str],
) -> PlanResult:
    """为一次重连/轮询规划“从本地状态安全前进”的更新链。

    versions: 全量已发布版本（含已撤销）。
    present:  该节点本地版本状态快照 {version_id: state}。
    """
    vmap = {v.id: v for v in versions}
    ops: list[ChainOp] = []
    blocked: list[dict] = []

    # 1) 本地仍持有、但控制端已撤销的版本：先回收，绝不允许激活。
    for vid, st in present.items():
        v = vmap.get(vid)
        if v is not None and v.revoked and st not in (REVOKED,):
            ops.append(ChainOp(RECALL, v, "version revoked by controller"))

    # 2) 计算每个作用域的安全起点。
    #    起点 = 最高“已激活”版本（之后的版本必须逐个前进）；
    #    没有激活版本时，任何已下载/校验中的版本及其前代都要重新进链，
    #    节点绝不跳过中间版本直接领取最新快照。
    activated: dict[str, int] = {}   # scope -> 最高已激活 seq
    for vid, st in present.items():
        v = vmap.get(vid)
        if v is None or v.revoked or st != ACTIVATED:
            continue
        activated[v.scope] = max(activated.get(v.scope, 0), v.seq)

    # 3) 组装每个作用域候选：从水位之后按 seq 排（含已下载/校验中的种子）
    by_scope: dict[str, list[Version]] = {}
    for v in sorted(versions, key=lambda x: x.seq):
        if not v.revoked and v.targets(node_id, node_region):
            by_scope.setdefault(v.scope, []).append(v)

    candidates: dict[str, list[Version]] = {}
    for scope, scope_versions in by_scope.items():
        floor = activated.get(scope, 0) + 1
        candidates[scope] = [x for x in scope_versions if x.seq >= floor]

    # 4) 多趟拓扑选择：同作用域严格按 seq 推进（队首不就绪，后续整列等待）；
    #    跨作用域每趟把所有“队首就绪”的候选按 (最高依赖seq, 作用域, seq) 全局排序，
    #    从而父版本链尽可能先走深，子版本紧跟其声明依赖，不盲目跳到最新版本。
    emitted: list[Version] = []
    emitted_ids: set[str] = set()
    permanent_blocked: set[str] = set()

    def dep_seqs(v: Version) -> list[int]:
        return [vmap[d].seq for d in v.deps.values() if d in vmap]

    def dep_ready(v: Version) -> bool:
        for dep_vid in v.deps.values():
            if present.get(dep_vid) == ACTIVATED:
                continue
            if dep_vid in emitted_ids:
                continue
            return False
        return True

    def dep_infeasible(v: Version) -> Optional[str]:
        """依赖永久无法在本节点满足：版本不存在/已撤销/不面向本节点。"""
        for dep_vid in v.deps.values():
            d = vmap.get(dep_vid)
            if d is None:
                return f"missing dependency {dep_vid}"
            if d.revoked:
                return f"dependency {dep_vid} revoked"
            if not d.targets(node_id, node_region):
                return f"dependency {dep_vid} not targeted to this node"
        return None

    while True:
        ready: list[Version] = []
        for scope in sorted(candidates):
            lst = candidates[scope]
            # 队首永久不可行（依赖被撤销/缺失/不面向本节点）则裁剪，
            # 它之后的同作用域版本才有机会被评估
            while lst:
                reason = dep_infeasible(lst[0])
                if reason is None:
                    break
                blocked.append({"scope": scope, "version_id": lst[0].id,
                                "reason": reason, "permanent": True})
                permanent_blocked.add(lst[0].id)
                lst.pop(0)
            if lst and dep_ready(lst[0]):
                ready.append(lst[0])
        if not ready:
            break
        ready.sort(key=lambda x: (max(dep_seqs(x), default=0), x.scope, x.seq))
        for v in ready:
            ops.append(ChainOp(APPLY, v, _why(v)))
            emitted.append(v)
            emitted_ids.add(v.id)
            candidates[v.scope].pop(0)

    # 剩余候选只是暂时等依赖（下一轮重连再试）
    for scope, lst in candidates.items():
        for v in lst:
            if v.id not in permanent_blocked:
                blocked.append({"scope": scope, "version_id": v.id,
                                "reason": "waiting dependencies",
                                "permanent": False})

    return PlanResult(ops=ops, blocked=blocked)


def _why(v: Version) -> str:
    if v.override:
        return f"emergency override for {v.scope}"
    if not v.deps:
        return f"advance {v.scope}"
    return f"advance {v.scope} after parent activation"


@dataclass
class ReceiptDecision:
    accepted: bool
    reason: str
    new_state: Optional[str] = None
    # 本次激活引发的同作用域旧版本连带状态迁移
    cascades: list[tuple[str, str]] = field(default_factory=list)


def decide_receipt(
    *,
    claimed_version_id: str,
    claimed_state: str,
    seq: int,
    sha256: Optional[str],
    high_water: int,
    last_seq: Optional[int],
    last_version_id: Optional[str],
    last_state: Optional[str],
    node_states: dict[str, str],          # 本节点全部 version -> state
    versions: dict[str, Version],
    active_versions_by_scope: dict[str, list[str]],  # scope -> 本节点当前激活版本id
) -> ReceiptDecision:
    """判定一条回执是否被接受（乱序/重复/倒退在这里被挡下）。

    调用方（service 层）负责持久化事务；本函数只做纯判定。
    """
    v = versions.get(claimed_version_id)
    if v is None:
        return ReceiptDecision(False, "unknown version")
    if claimed_state not in RANK:
        return ReceiptDecision(False, f"unknown state {claimed_state}")

    # --- 序号防线：严格 +1；旧序号/空洞都不接受 ---
    if seq <= high_water:
        # 与“上一次已接受回执”完全相同 => 幂等重投，返回成功但不改状态
        if (seq == last_seq and claimed_version_id == last_version_id
                and claimed_state == last_state):
            return ReceiptDecision(True, "duplicate (already applied)", new_state=claimed_state)
        return ReceiptDecision(False, f"stale receipt seq={seq} <= high_water={high_water}")
    if seq != high_water + 1:
        return ReceiptDecision(False, f"gap: expected seq={high_water + 1}, got {seq}")

    # 已撤销版本不接受任何前进回执（节点应走 RECALL）
    if v.revoked and claimed_state != REVOKED:
        return ReceiptDecision(False, f"{claimed_version_id} is revoked")

    cur = node_states.get(claimed_version_id)

    # 同状态重放（节点重启后重发）幂等
    if cur == claimed_state:
        return ReceiptDecision(True, "duplicate (same state)", new_state=cur)

    rank = RANK[claimed_state]

    # --- 终态语义 ---
    if claimed_state == REVOKED:
        if not v.revoked:
            return ReceiptDecision(False, "version is not revoked")
        # 节点可能在首次 pull 时才得知撤销（控制端此前无记录），幂等接受
        return ReceiptDecision(True, "revoked", new_state=REVOKED)

    if claimed_state in (SUPERSEDED, REPLACED):
        if cur != ACTIVATED:
            return ReceiptDecision(False, f"cannot mark {claimed_state} from {cur}")
        active = [x for x in active_versions_by_scope.get(v.scope, []) if x != v.id]
        if claimed_state == SUPERSEDED:
            if not any(versions[x].override for x in active if x in versions):
                return ReceiptDecision(False, "no active override supersedes this version")
        else:
            if not active:
                return ReceiptDecision(False, "no newer active version replaces this one")
        return ReceiptDecision(True, claimed_state.lower(), new_state=claimed_state)

    # --- 前进态：DOWNLOADED -> VERIFIED -> ACTIVATED ---
    expected_prev = {VERIFIED: DOWNLOADED, ACTIVATED: VERIFIED}
    if claimed_state in expected_prev:
        need = expected_prev[claimed_state]
        if cur != need:
            # 允许节点把相邻两阶段合并上报（少见，但容错）
            if RANK.get(cur, 0) >= rank:
                return ReceiptDecision(False, f"regression {cur} -> {claimed_state}")
            if claimed_state == ACTIVATED and cur != VERIFIED:
                return ReceiptDecision(False, f"cannot activate from {cur}")
            if claimed_state == VERIFIED and cur != DOWNLOADED:
                return ReceiptDecision(False, f"cannot verify from {cur}")

    if claimed_state == DOWNLOADED and cur is not None and RANK[cur] >= rank:
        return ReceiptDecision(False, f"regression {cur} -> DOWNLOADED")

    # 哈希校验（REVOKED/SUPERSEDED/REPLACED 不需要）
    if claimed_state in (DOWNLOADED, VERIFIED, ACTIVATED):
        if not sha256 or sha256 != v.content_sha256:
            return ReceiptDecision(False, "content sha256 mismatch")

    # 激活闸门：所有声明依赖的父版本必须曾在本节点“抵达”。
    # 抵达 = 已激活（ACTIVATED）或曾激活后被替换/覆盖（REPLACED/SUPERSEDED）；
    # REVOKED 不算安全抵达。
    if claimed_state == ACTIVATED:
        for dep_scope, dep_vid in v.deps.items():
            dep = versions.get(dep_vid)
            if dep is None or dep.revoked:
                return ReceiptDecision(False, f"dependency {dep_vid} unavailable")
            if node_states.get(dep_vid) not in (ACTIVATED, REPLACED, SUPERSEDED):
                return ReceiptDecision(
                    False, f"parent {dep_vid} never reached this node")

    # 激活成功后的连带迁移：同作用域其它激活版本
    cascades: list[tuple[str, str]] = []
    if claimed_state == ACTIVATED:
        for other_id in active_versions_by_scope.get(v.scope, []):
            if other_id == v.id:
                continue
            other = versions.get(other_id)
            if other is None:
                continue
            new = SUPERSEDED if other.override and not v.override else REPLACED
            # 反向（普通版本 -> 覆盖）也记 SUPERSEDED
            if v.override and not other.override:
                new = SUPERSEDED
            cascades.append((other_id, new))

    return ReceiptDecision(True, "accepted", new_state=claimed_state, cascades=cascades)


def can_revoke(version: Version, node_states: dict[str, str]) -> tuple[bool, str]:
    """撤销闸门：任一节点激活过（含被覆盖/替换）即不可撤销。"""
    if version.revoked:
        return False, "already revoked"
    activated_on = [n for n, st in node_states.items()
                    if st in (ACTIVATED, SUPERSEDED, REPLACED)]
    if activated_on:
        return False, f"already live on nodes: {', '.join(sorted(activated_on))}"
    return True, "ok"
