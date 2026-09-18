"""端到端冒烟：起真实控制面 HTTP，用 urllib 模拟节点/代理行为，
覆盖完整三态回执、重复乱序、撤销回收、紧急覆盖、离线重连链。"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def post(base, path, payload):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read().decode())


class E2ETest(unittest.TestCase):
    proc = None
    tmp = None
    base = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        env = dict(os.environ, CONTROLLER_DB=os.path.join(cls.tmp, "c.db"),
                   CONTROLLER_PORT="18099", SIGNING_SECRET="e2e-secret")
        cls.proc = subprocess.Popen(
            [sys.executable, str(APP_DIR / "server.py")],
            cwd=APP_DIR, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        cls.base = "http://127.0.0.1:18099"
        for _ in range(50):
            try:
                get(cls.base, "/healthz")
                return
            except Exception:
                time.sleep(0.1)
        cls.proc.kill()
        raise RuntimeError("controller failed to start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)

    def run_agent_once(self, node, region, state_dir):
        env = dict(os.environ, CONTROLLER_URL=self.base, SIGNING_SECRET="e2e-secret",
                   STATE_FILE=os.path.join(state_dir, "agent.json"))
        r = subprocess.run(
            [sys.executable, str(APP_DIR / "agent.py"),
             "--id", node, "--region", region, "--once"],
            cwd=APP_DIR, env=env, capture_output=True, text=True, timeout=20)
        return r

    def test_end_to_end(self):
        # 发布 base@1，policy@1 依赖 base@1
        _, b1 = post(self.base, "/v1/versions",
                     {"scope": "base", "content": "base-config-v1"})
        _, p1 = post(self.base, "/v1/versions",
                     {"scope": "policy", "parent_scope": "base",
                      "content": "policy-v1", "deps": {"base": b1["version_id"]}})

        d1 = tempfile.mkdtemp()
        out1 = self.run_agent_once("edge-cn", "cn", d1)
        self.assertEqual(out1.returncode, 0, out1.stdout)
        self.assertIn("ACTIVATED", out1.stdout)
        detail = get(self.base, "/v1/nodes/edge-cn")
        self.assertEqual(detail["states"]["base@1"], "ACTIVATED")
        self.assertEqual(detail["states"]["policy@1"], "ACTIVATED")

        # 再跑一次：应 in sync，且重复上报不会倒退
        out1b = self.run_agent_once("edge-cn", "cn", d1)
        self.assertIn("in sync", out1b.stdout)

        # 发布 base@2 并立即撤销；节点已在本地不会有它 -> 不激活
        _, b2 = post(self.base, "/v1/versions",
                     {"scope": "base", "content": "base-config-v2-bad"})
        status, _ = post(self.base, f"/v1/versions/{b2['version_id']}/revoke", {})
        self.assertEqual(status, 200)
        out1c = self.run_agent_once("edge-cn", "cn", d1)
        self.assertNotIn("base@2", out1c.stdout.replace("RECALL", ""))

        # base@3 正常升级
        _, b3 = post(self.base, "/v1/versions",
                     {"scope": "base", "content": "base-config-v3"})
        self.run_agent_once("edge-cn", "cn", d1)
        detail = get(self.base, "/v1/nodes/edge-cn")
        self.assertEqual(detail["states"]["base@3"], "ACTIVATED")
        self.assertEqual(detail["states"]["base@1"], "REPLACED")

        # 针对 cn 的紧急覆盖
        _, ov = post(self.base, "/v1/versions",
                     {"scope": "policy", "content": "EMERGENCY-cn",
                      "override": True, "target_regions": ["cn"]})
        self.run_agent_once("edge-cn", "cn", d1)
        detail = get(self.base, "/v1/nodes/edge-cn")
        self.assertEqual(detail["states"][ov["version_id"]], "ACTIVATED")
        self.assertEqual(detail["states"]["policy@1"], "SUPERSEDED")

        # EU 新节点：不收到紧急覆盖
        d_eu = tempfile.mkdtemp()
        self.run_agent_once("edge-eu", "eu", d_eu)
        detail_eu = get(self.base, "/v1/nodes/edge-eu")
        self.assertNotIn(ov["version_id"], detail_eu["states"])
        self.assertEqual(detail_eu["states"]["policy@1"], "ACTIVATED")

        # 长离线节点全新重连：拿到完整有序安全链，不含撤销版本
        d_late = tempfile.mkdtemp()
        out_late = self.run_agent_once("edge-late", "cn", d_late)
        detail_late = get(self.base, "/v1/nodes/edge-late")
        self.assertEqual(detail_late["states"]["base@1"], "REPLACED")
        self.assertEqual(detail_late["states"]["base@3"], "ACTIVATED")
        self.assertNotIn("base@2", detail_late["states"])
        self.assertEqual(detail_late["states"][ov["version_id"]], "ACTIVATED")
        self.assertEqual(detail_late["states"]["policy@1"], "SUPERSEDED")
        # 链顺序（从日志验证父先于子、覆盖最后）
        self.assertLess(out_late.stdout.index("base@1 ACTIVATED"),
                        out_late.stdout.index("policy@1 ACTIVATED"))
        self.assertLess(out_late.stdout.index("base@3 ACTIVATED"),
                        out_late.stdout.index(f"{ov['version_id']} ACTIVATED"))

        # 回执防线：旧 seq 重放（幂等 vs 篡改）、空洞 seq、倒退状态
        hw = detail_late["high_water"]
        s, old = post(self.base, "/v1/nodes/edge-late/receipts",
                      {"region": "cn", "seq": 1,
                       "version_id": "base@1", "state": "DOWNLOADED",
                       "sha256": b1["content_sha256"]})
        # 与历史完全一致的重投：幂等，不改状态
        self.assertTrue(old["duplicate"])
        self.assertTrue(old["accepted"])
        # 借旧 seq 篡改内容（换版本号）：拒绝
        s, tamper = post(self.base, "/v1/nodes/edge-late/receipts",
                         {"region": "cn", "seq": 1,
                          "version_id": "base@3", "state": "DOWNLOADED",
                          "sha256": b3["content_sha256"]})
        self.assertFalse(tamper["accepted"])
        self.assertIn("stale", tamper["reason"])
        s, gap = post(self.base, "/v1/nodes/edge-late/receipts",
                      {"region": "cn", "seq": hw + 5,
                       "version_id": "base@3", "state": "ACTIVATED",
                       "sha256": b3["content_sha256"]})
        self.assertFalse(gap["accepted"])
        # 错误 sha256
        s, bad = post(self.base, "/v1/nodes/edge-late/receipts",
                      {"region": "cn", "seq": hw + 1,
                       "version_id": "base@3", "state": "DOWNLOADED",
                       "sha256": "0" * 64})
        self.assertFalse(bad["accepted"])
        # 激活后被覆盖的版本不能被旧回执倒退
        s, back = post(self.base, "/v1/nodes/edge-late/receipts",
                       {"region": "cn", "seq": hw + 2,
                        "version_id": "policy@1", "state": "VERIFIED"})
        self.assertFalse(back["accepted"])


if __name__ == "__main__":
    unittest.main()
