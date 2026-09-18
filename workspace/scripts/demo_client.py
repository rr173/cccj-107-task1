#!/usr/bin/env python3
"""演示用控制面 API 客户端（仅标准库）。

子命令：
  health / bootstrap / publish-and-revoke / publish-v3-and-override /
  wait-activated <node> <version> [timeout] / show / node <id> / receipt-attacks
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

STATE_LABEL = {
    "DOWNLOADED": "已下载", "VERIFIED": "已校验", "ACTIVATED": "已激活",
    "SUPERSEDED": "被覆盖", "REPLACED": "被替换", "REVOKED": "已撤销",
}


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, payload=None):
        data = json.dumps(payload or {}).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def post(self, path, payload=None):
        return self.call("POST", path, payload)

    def get(self, path):
        return self.call("GET", path)


def cmd_health(c: Client, args):
    st, body = c.get("/healthz")
    print(json.dumps(body, ensure_ascii=False))
    return st == 200


def cmd_bootstrap(c: Client, args):
    for name, parent in [("system", None), ("base", "system"),
                         ("policy", "base")]:
        st, body = c.post("/v1/scopes", {"name": name, "parent": parent})
        assert st == 200, body
    st, b1 = c.post("/v1/versions",
                    {"scope": "system", "content": "system-core v1"})
    assert st == 201, b1
    st, base1 = c.post("/v1/versions",
                       {"scope": "base", "content": '{"tls": "1.2", "rate": 100}'})
    assert st == 201, base1
    st, p1 = c.post("/v1/versions", {
        "scope": "policy",
        "content": '{"rules": ["allow /healthz", "deny /admin"]}',
        "deps": {"base": "base@1"}})
    assert st == 201, p1
    print(f"  发布 system@1 / base@1(sha {base1['content_sha256'][:12]}…) / policy@1")
    print("  policy@1 声明依赖 base@1：父版本未激活前子版本不能生效")


def cmd_publish_and_revoke(c: Client, args):
    st, b2 = c.post("/v1/versions",
                    {"scope": "base", "content": '{"rate": 999}  # 有问题的配置'})
    assert st == 201, b2
    st, p2 = c.post("/v1/versions", {
        "scope": "policy", "content": '{"rules": ["risky"]}',
        "deps": {"base": "base@2"}})
    assert st == 201, p2
    print(f"  发布 {b2['version_id']} 与 {p2['version_id']}")
    st, r = c.post(f"/v1/versions/{b2['version_id']}/revoke", {})
    print(f"  撤销 {b2['version_id']} -> {r}")
    assert st == 200, r
    # policy@2 依赖已撤销的 base@2：会永远留在 blocked，不会有节点激活
    # 撤销已经在某节点激活的版本会被 409 拒绝，这里顺带验证
    st, denied = c.post("/v1/versions/base@1/revoke", {})
    print(f"  尝试撤销已扩散的 base@1 -> HTTP {st} ({denied['error']}: {denied['message']})")
    assert st == 409


def cmd_publish_v3_and_override(c: Client, args):
    st, b3 = c.post("/v1/versions",
                    {"scope": "base", "content": '{"tls": "1.3", "rate": 120}'})
    assert st == 201, b3
    st, p3 = c.post("/v1/versions", {
        "scope": "policy",
        "content": '{"rules": ["allow /healthz", "allow /v2", "deny /admin"]}',
        "deps": {"base": "base@3"}})
    assert st == 201, p3
    print(f"  发布 {b3['version_id']} 与 {p3['version_id']}（正常全球扩散）")
    st, ov = c.post("/v1/versions", {
        "scope": "policy",
        "content": '{"rules": ["EMERGENCY: fail-open cn only"]}',
        "override": True, "target_regions": ["cn"]})
    assert st == 201, ov
    print(f"  发布紧急覆盖 {ov['version_id']}，仅定向 region=cn")
    print("  eu/us 节点不会收到该覆盖；cn 上 policy@3 将变为 SUPERSEDED(被覆盖)")


def _wait(c, node, version, want, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, body = c.get(f"/v1/nodes/{node}")
        if st == 200 and body["states"].get(version) == want:
            return True, body
        time.sleep(1)
    return False, body if st == 200 else {}


def cmd_wait_activated(c, args):
    ok, body = _wait(c, args.node, args.version, "ACTIVATED", args.timeout)
    if not ok:
        print(f"!! 超时：{args.node} 的 {args.version} 未激活")
        print(json.dumps(body, ensure_ascii=False, indent=2))
        sys.exit(2)
    print(f"  ✓ {args.node}: {args.version} 已激活 "
          f"(回执水位 hw_seq={body['high_water']})")


def cmd_show(c: Client, args):
    _, nodes = c.get("/v1/nodes")
    _, versions = c.get("/v1/versions")
    print("节点：")
    for n in nodes["nodes"]:
        print(f"  - {n['id']:<12} region={n['region']:<3} "
              f"hw_seq={n['high_water']:<3} last_seen={n['last_seen']}")
    print("版本传播：")
    for v in versions["versions"]:
        flags = []
        if v["revoked"]:
            flags.append("已撤销")
        if v["override"]:
            flags.append("紧急覆盖")
        print(f"  {v['version_id']:<10} {'/'.join(flags) or '常规版本'}")
        for state, items in sorted(v["states"].items()):
            who = ", ".join(f"{x['node']}({x['region']})" for x in items)
            print(f"      {STATE_LABEL.get(state, state):<5} [{state}] -> {who}")


def cmd_node(c: Client, args):
    st, body = c.get(f"/v1/nodes/{args.id}")
    if st != 200:
        print(body)
        sys.exit(1)
    print(f"节点 {body['id']} ({body['region']}) 回执水位={body['high_water']}")
    print("版本状态：")
    for vid, stt in sorted(body["states"].items()):
        print(f"  {vid:<10} -> {stt}")
    print("最近回执（最新在上）：")
    for r in body["receipts"][:12]:
        mark = "✓" if r["accepted"] else "✗"
        print(f"  {mark} seq={r['seq']:<3} {r['version_id']:<10} "
              f"{r['state']:<11} {r['reason']}")


def cmd_receipt_attacks(c: Client, args):
    # 每次使用唯一探针节点，避免上一轮攻击 seq 污染本次水位演示
    import os
    import subprocess
    import tempfile
    import time as _time
    probe = f"probe-{int(_time.time())}"
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    state_dir = tempfile.mkdtemp(prefix="probe-")
    env = dict(os.environ, CONTROLLER_URL=c.base, STATE_FILE=state_dir + "/agent.json",
               SIGNING_SECRET=os.environ.get("SIGNING_SECRET", "shared-demo-secret"))
    r = subprocess.run(
        [sys.executable, os.path.join(here, "app", "agent.py"),
         "--id", probe, "--region", "cn", "--once"],
        env=env, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
        raise RuntimeError("probe agent failed")
    # cn 区域最终激活的是紧急覆盖 policy@4（policy@1 已被 REPLACED/SUPERSEDED）
    ok, body = _wait(c, probe, "policy@4", "ACTIVATED", 40)
    assert ok, f"{probe} 未能激活 policy@4"
    hw = body["high_water"]

    attacks = [
        ("旧 seq=1 但篡改版本（想借重放把 base@3 拉回 DOWNLOADED）",
         lambda hw: 1, "base@3", "DOWNLOADED", lambda: _hash_of(c, "base@3")),
        ("乱序空洞（跳过下一个序号）",
         lambda hw: hw + 5, "policy@4", "ACTIVATED",
         lambda: _hash_of(c, "policy@4")),
        ("错误内容哈希",
         lambda hw: hw + 1, "base@3", "DOWNLOADED", lambda: "0" * 64),
        ("状态倒退：已被替换的 policy@1 退回 VERIFIED",
         lambda hw: hw + 1, "policy@1", "VERIFIED", lambda: None),
    ]

    for desc, seq_fn, vid, state, sha_fn in attacks:
        # 注意：确定性拒绝（恰好下一个序号但内容非法）也会推进水位，
        # 所以每次攻击前重新读取当前 hw
        _, cur = c.get(f"/v1/nodes/{probe}")
        payload = {"region": "cn", "seq": seq_fn(cur["high_water"]),
                   "version_id": vid, "state": state}
        sha = sha_fn()
        if sha:
            payload["sha256"] = sha
        st, resp = c.post(f"/v1/nodes/{probe}/receipts", payload)
        verdict = "拒绝" if not resp.get("accepted") else "接受(!!)"
        print(f"  {desc}\n    -> {verdict}: {resp['reason']}")
        assert not resp.get("accepted"), f"防线失效: {desc}"

    # 合法重复回执：先补一条合法的下一序号回执（让节点状态再次合法推进），
    # 再原样重放同一条，必须幂等接受而不是重复推进。
    _, cur = c.get(f"/v1/nodes/{probe}")
    hw = cur["high_water"]
    st, first = c.post(f"/v1/nodes/{probe}/receipts", {
        "region": "cn", "seq": hw + 1,
        "version_id": "system@1", "state": "ACTIVATED",
        "sha256": _hash_of(c, "system@1")})
    # system@1 已是 ACTIVATED -> 同状态幂等 accepted
    assert first.get("accepted"), first
    st, again = c.post(f"/v1/nodes/{probe}/receipts", {
        "region": "cn", "seq": hw + 1,
        "version_id": "system@1", "state": "ACTIVATED",
        "sha256": _hash_of(c, "system@1")})
    print(f"  合法下一序号同状态回执 -> {first['reason']}")
    print(f"  原样重放该回执(seq={hw + 1}) -> 幂等: {again['reason']}")
    assert again.get("duplicate")


def _versions(c: Client):
    _, body = c.get("/v1/versions")
    return body["versions"]


def _hash_of(c: Client, vid):
    # 用新的 cn 节点 pull，从操作内容里取真实哈希
    _, plan = c.post("/v1/nodes/_hashprobe/pull",
                     {"region": "cn", "present": {}})
    for op in plan["ops"]:
        if op["version_id"] == vid:
            return op["content_sha256"]
    raise RuntimeError(f"hash for {vid} not found")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8080")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    sub.add_parser("bootstrap")
    sub.add_parser("publish-and-revoke")
    sub.add_parser("publish-v3-and-override")
    sub.add_parser("show")
    w = sub.add_parser("wait-activated")
    w.add_argument("node")
    w.add_argument("version")
    w.add_argument("timeout", type=int, nargs="?", default=40)
    n = sub.add_parser("node")
    n.add_argument("id")
    sub.add_parser("receipt-attacks")
    args = p.parse_args()

    c = Client(args.base)
    handlers = {
        "health": cmd_health, "bootstrap": cmd_bootstrap,
        "publish-and-revoke": cmd_publish_and_revoke,
        "publish-v3-and-override": cmd_publish_v3_and_override,
        "wait-activated": cmd_wait_activated, "show": cmd_show,
        "node": cmd_node, "receipt-attacks": cmd_receipt_attacks,
    }
    ok = handlers[args.cmd](c, args)
    sys.exit(0 if ok is not False else 1)


if __name__ == "__main__":
    main()
