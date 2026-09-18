"""边缘节点代理。

职责：
  1. 轮询控制端，上报本地版本状态，领取“可从本地安全前进”的操作链。
  2. APPLY: 下载 -> 校验 sha256(+HMAC 签名) -> 满足父版本闸门后激活。
  3. RECALL: 丢弃本地持有的已撤销版本。
  4. 覆盖/替换语义：激活新版本时本地迁移旧版本状态并补发回执。
  5. 回执严格按节点本地 seq 顺序发送（at-least-once，控制端去重）。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Optional

DOWNLOADED = "DOWNLOADED"
VERIFIED = "VERIFIED"
ACTIVATED = "ACTIVATED"
SUPERSEDED = "SUPERSEDED"
REPLACED = "REPLACED"
REVOKED = "REVOKED"
TERMINAL = {SUPERSEDED, REPLACED, REVOKED}


class ControllerClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def _call(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.base + path, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def pull(self, node_id: str, region: str, present: dict) -> dict:
        return self._call(f"/v1/nodes/{node_id}/pull",
                          {"region": region, "present": present})

    def receipt(self, node_id: str, region: str, seq: int,
                version_id: str, state: str, sha256: Optional[str]) -> dict:
        body = {"region": region, "seq": seq,
                "version_id": version_id, "state": state}
        if sha256:
            body["sha256"] = sha256
        return self._call(f"/v1/nodes/{node_id}/receipts", body)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class Agent:
    def __init__(self, node_id: str, region: str, controller: str,
                 state_file: str, secret: str, poll_interval: float = 2.0,
                 once: bool = False):
        self.node_id = node_id
        self.region = region
        self.client = ControllerClient(controller)
        self.state_file = state_file
        self.secret = secret
        self.poll_interval = poll_interval
        self.once = once
        self._pending: dict[str, Any] = {}
        self.state = self._load()

    # ---------- 本地持久化 ----------
    def _load(self) -> dict:
        if os.path.exists(self.state_file):
            with open(self.state_file, encoding="utf-8") as f:
                return json.load(f)
        return {"next_seq": 1, "versions": {}}   # version_id -> {state, content, sha}

    def _save(self) -> None:
        tmp = self.state_file + ".tmp"
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.state_file)

    def log(self, msg: str) -> None:
        print(f"[edge-{self.region}:{self.node_id}] {msg}", flush=True)

    # ---------- 回执 ----------
    def _send_receipt(self, version_id: str, state: str,
                      sha: Optional[str]) -> Optional[dict]:
        """按本地严格递增 seq 发送。返回控制端响应；网络失败返回 None。"""
        seq = self.state["next_seq"]
        try:
            resp = self.client.receipt(
                self.node_id, self.region, seq, version_id, state, sha)
        except urllib.error.URLError as e:
            self.log(f"receipt seq={seq} {version_id}/{state} NETWORK-FAIL ({e}); will retry")
            return None
        if resp.get("duplicate"):
            self.log(f"receipt seq={seq} duplicate -> {resp.get('state')}")
        self.state["next_seq"] = max(self.state["next_seq"],
                                     resp.get("high_water", seq) + 1)
        self._save()
        return resp

    def _report(self, version_id: str, state: str,
                sha: Optional[str] = None) -> bool:
        """发送回执；接受后迁移本地已有记录的状态（记录由 _apply 建）。"""
        resp = self._send_receipt(version_id, state, sha)
        if resp is None:
            return False
        if resp.get("duplicate") or resp.get("accepted"):
            if version_id in self.state["versions"]:
                self.state["versions"][version_id]["state"] = state
                self._save()
            return True
        self.log(f"receipt {version_id}/{state} REJECTED: {resp.get('reason')}")
        return False

    # ---------- 操作执行 ----------
    def _check_content(self, op: dict) -> bool:
        sha = _sha256(op["content"])
        if sha != op["content_sha256"]:
            self.log(f"{op['version_id']} sha256 mismatch, refuse")
            return False
        if op.get("signature") and self.secret:
            expect = hmac.new(self.secret.encode(), op["content"].encode(),
                              hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expect, op["signature"]):
                self.log(f"{op['version_id']} HMAC signature mismatch, refuse")
                return False
        return True

    def _deps_active(self, op: dict, chain_activated: set[str]) -> bool:
        arrived = {ACTIVATED, REPLACED, SUPERSEDED}
        for dep_vid in (op.get("deps") or {}).values():
            if dep_vid in chain_activated:
                continue
            rec = self.state["versions"].get(dep_vid)
            if not rec or rec.get("state") not in arrived:
                self.log(f"{op['version_id']} waiting parent {dep_vid} to arrive")
                return False
        return True

    def _cascade_old_actives(self, op: dict, new_state_for_old: str) -> None:
        """激活时本地迁移同作用域旧激活版本，并补发回执。"""
        scope = op["scope"]
        for vid, rec in list(self.state["versions"].items()):
            if rec.get("state") != ACTIVATED or vid == op["version_id"]:
                continue
            # 仅知道作用域时，用回执让控制端裁决；本地按 op 版本记录的 scope 过滤
            rec_scope = vid.rsplit("@", 1)[0]
            if rec_scope != scope:
                continue
            rec["state"] = new_state_for_old
            self._save()
            self._report(vid, new_state_for_old, rec.get("sha"))

    def _apply(self, op: dict, chain_activated: set[str]) -> None:
        vid = op["version_id"]
        local = self.state["versions"].get(vid, {})
        state = local.get("state")

        if state is None:
            if not self._check_content(op):
                return
            # 内容只在本轮内存中持有；回执被接受后才落 DOWNLOADED，
            # 崩溃/拒绝则下一轮重新下载，保证本地状态不超前于控制端。
            self._pending = {"content": op["content"], "sha": op["content_sha256"]}
            if not self._report(vid, DOWNLOADED, op["content_sha256"]):
                return
            self.state["versions"][vid] = dict(self._pending, state=DOWNLOADED)
            self._save()
            state = DOWNLOADED
            self.log(f"{vid} downloaded [{op.get('reason')}]")
        elif state in TERMINAL:
            return
        if state == DOWNLOADED:
            if not self._report(vid, VERIFIED, op["content_sha256"]):
                return
            state = VERIFIED
            self.log(f"{vid} verified")

        # 激活闸门：父版本必须已在本地激活，或在本安全链中更早激活
        if not self._deps_active(op, chain_activated):
            self.log(f"{vid} held VERIFIED, will activate after parent arrives")
            return

        if state == VERIFIED:
            if not self._report(vid, ACTIVATED, op["content_sha256"]):
                return
            chain_activated.add(vid)
            self.log(f"{vid} ACTIVATED: {op['content'][:80]}")

            # 同作用域旧激活版本：覆盖 -> SUPERSEDED，普通升级 -> REPLACED
            old_state = SUPERSEDED if op.get("override") else REPLACED
            self._cascade_old_actives(op, old_state)

    def _reconcile(self, items: list[dict]) -> None:
        """控制端权威状态与本地不一致时，补发幂等回执对齐。"""
        for item in items:
            vid, want = item["version_id"], item["state"]
            local = self.state["versions"].get(vid, {})
            if local.get("state") == want:
                continue
            self.log(f"reconcile {vid}: local={local.get('state')} controller={want}")
            if vid not in self.state["versions"]:
                # 控制端有记录而本地丢失（如崩溃在落盘前）：补最小记录对齐
                self.state["versions"][vid] = {"state": want}
                self._save()
            self._report(vid, want, local.get("sha"))
            if want == REVOKED:
                rec = self.state["versions"].get(vid)
                if rec:
                    rec.pop("content", None)

    def _recall(self, op: dict) -> None:
        vid = op["version_id"]
        rec = self.state["versions"].get(vid)
        if rec and rec.get("state") != REVOKED:
            if not self._report(vid, REVOKED, None):
                return
            rec["state"] = REVOKED
            rec.pop("content", None)
            self._save()
            self.log(f"{vid} RECALLED ({op.get('reason')})")

    # ---------- 主循环 ----------
    def poll_once(self) -> tuple[bool, int]:
        """返回 (网络是否成功, 本轮处理的操作数)。"""
        present = {vid: rec["state"] for vid, rec in self.state["versions"].items()}
        try:
            resp = self.client.pull(self.node_id, self.region, present)
        except urllib.error.URLError as e:
            self.log(f"pull failed: {e}; keep local state, retry later")
            return False, 0
        ops = resp.get("ops", [])
        reconcile = resp.get("reconcile", [])
        if reconcile:
            self._reconcile(reconcile)
        if not ops:
            self.log(f"in sync (hw={resp.get('high_water')}, "
                     f"local receipts next_seq={self.state['next_seq']})")
            return True, 0
        chain_activated: set[str] = set()
        for op in ops:
            if op["type"] == "RECALL":
                self._recall(op)
            else:
                self._apply(op, chain_activated)
        return True, len(ops)

    def run(self) -> None:
        self.log(f"starting; controller={self.client.base} state={self.state_file}")
        if self.once:
            # 多轮收敛：一条链含多个操作，每个操作 3 条串行回执，
            # 后序操作的父依赖可能要到下一轮 pull 才能在控制端观测到。
            for _ in range(10):
                ok, worked = self.poll_once()
                if not ok or worked == 0:
                    break
            return
        while True:
            try:
                self.poll_once()
            except Exception as e:  # noqa: BLE001
                self.log(f"poll error: {e}")
            time.sleep(self.poll_interval)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--id", default=os.environ.get("NODE_ID", "node"))
    p.add_argument("--region", default=os.environ.get("NODE_REGION", "default"))
    p.add_argument("--controller", default=os.environ.get("CONTROLLER_URL", "http://controller:8080"))
    p.add_argument("--state-file", default=os.environ.get("STATE_FILE", "/data/agent.json"))
    p.add_argument("--secret", default=os.environ.get("SIGNING_SECRET", "dev-shared-secret"))
    p.add_argument("--interval", type=float, default=float(os.environ.get("POLL_INTERVAL", "2")))
    p.add_argument("--once", action="store_true")
    args = p.parse_args()
    Agent(args.id, args.region, args.controller, args.state_file,
          args.secret, args.interval, args.once).run()


if __name__ == "__main__":
    main()
