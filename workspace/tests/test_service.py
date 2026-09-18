"""服务层 + 存储的集成测试（内存 SQLite）。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from service import Service, ServiceError
from storage import Store


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.svc = Service(Store(":memory:"), signing_secret="s3cr3t")

    def publish_base(self, n=1, **kw):
        return self.svc.publish(scope="base", content=f"b{n}", **kw)

    def test_publish_validates_ancestor_dependency(self):
        self.svc.ensure_scope("base")
        self.svc.ensure_scope("policy", parent="base")
        b = self.publish_base()
        # 非祖先作用域依赖被拒
        with self.assertRaises(ServiceError):
            self.svc.publish(scope="other", content="x",
                             deps={"base": b["version_id"]},
                             parent_scope=None)
        # 依赖一个不存在的版本
        with self.assertRaises(ServiceError):
            self.svc.publish(scope="policy", content="p1",
                             deps={"base": "base@99"})

    def test_override_requires_targets(self):
        with self.assertRaises(ServiceError):
            self.svc.publish(scope="policy", content="x", override=True)

    def test_pull_and_receipt_full_lifecycle_and_chain(self):
        self.svc.ensure_scope("base")
        self.svc.ensure_scope("policy", parent="base")
        b1 = self.publish_base(1)
        b2 = self.publish_base(2)
        p1 = self.svc.publish(scope="policy", content="p1",
                              deps={"base": b1["version_id"]})
        p2 = self.svc.publish(scope="policy", content="p2",
                              deps={"base": b2["version_id"]})

        # 全新节点拉取：顺序链
        plan = self.svc.pull("n-cn", "cn", {})
        vids = [(op["type"], op["version_id"]) for op in plan["ops"]]
        self.assertEqual(vids, [("APPLY", "base@1"), ("APPLY", "base@2"),
                                ("APPLY", "policy@1"), ("APPLY", "policy@2")])
        self.assertIn("reconcile", plan)

        def ack(vid, state, sha):
            seq = self.svc.store.get_node("n-cn")["hw_seq"] + 1
            r = self.svc.receipt("n-cn", "cn", seq, vid, state, sha)
            self.assertTrue(r["accepted"], r["reason"])

        h_b1 = b1["content_sha256"]
        # 未激活父版本就想激活子版本 -> 拒绝
        ack("base@1", "DOWNLOADED", h_b1)
        ack("base@1", "VERIFIED", h_b1)
        ack("base@1", "ACTIVATED", h_b1)
        seq = self.svc.store.get_node("n-cn")["hw_seq"] + 1
        bad = self.svc.receipt("n-cn", "cn", seq, "policy@1", "ACTIVATED",
                               p1["content_sha256"])
        self.assertFalse(bad["accepted"])

        # 旧序号但与已记录完全一致（重投）：幂等接受、不改状态
        dup_old = self.svc.receipt("n-cn", "cn", 1, "base@1", "DOWNLOADED", h_b1)
        self.assertTrue(dup_old["duplicate"])
        self.assertTrue(dup_old["accepted"])
        # 旧序号但内容不同（想借重放改写历史）：拒绝，不推进水位
        stale = self.svc.receipt("n-cn", "cn", 1, "base@2", "DOWNLOADED", h_b1)
        self.assertFalse(stale["accepted"])
        self.assertIn("stale", stale["reason"])

        # 乱序空洞：拒绝、不落库、不推进水位；之后合法的下一序号仍可接受
        hw_now = self.svc.store.get_node("n-cn")["hw_seq"]
        gap = self.svc.receipt("n-cn", "cn", hw_now + 5,
                               "base@2", "ACTIVATED", None)
        self.assertFalse(gap["accepted"])
        self.assertIn("gap", gap["reason"])
        self.assertIsNone(self.svc.store.receipt_at("n-cn", hw_now + 5))
        self.assertEqual(int(self.svc.store.get_node("n-cn")["hw_seq"]), hw_now)

        # 完全重复的回执（重投）幂等
        dup = self.svc.receipt("n-cn", "cn", seq, "policy@1", "ACTIVATED",
                               p1["content_sha256"])
        self.assertTrue(dup["duplicate"])

        # 错误哈希被拒
        nxt = self.svc.store.get_node("n-cn")["hw_seq"] + 1
        badhash = self.svc.receipt("n-cn", "cn", nxt, "base@2",
                                   "DOWNLOADED", "deadbeef")
        self.assertFalse(badhash["accepted"])

    def test_revoke_before_diffusion_and_recall(self):
        b1 = self.publish_base(1)
        b2 = self.publish_base(2)
        # 立即撤销（无任何节点激活）-> 成功
        r = self.svc.revoke("base@2")
        self.assertTrue(r["revoked"])
        # 重复撤销 -> 拒绝
        with self.assertRaises(ServiceError):
            self.svc.revoke("base@2")

        # 节点声称本地下载过 base@2：拉取得到 RECALL，且链里没有 base@2
        plan = self.svc.pull("n1", "cn", {"base@2": "DOWNLOADED"})
        self.assertEqual([(o["type"], o["version_id"]) for o in plan["ops"]],
                         [("RECALL", "base@2"), ("APPLY", "base@1")])
        rr = self.svc.receipt("n1", "cn", 1, "base@2", "REVOKED", None)
        self.assertTrue(rr["accepted"])

    def test_revoke_blocked_after_activation(self):
        self.publish_base(1)
        plan = self.svc.pull("n1", "cn", {})
        h = plan["ops"][0]["content_sha256"]
        self.svc.receipt("n1", "cn", 1, "base@1", "DOWNLOADED", h)
        self.svc.receipt("n1", "cn", 2, "base@1", "VERIFIED", h)
        self.svc.receipt("n1", "cn", 3, "base@1", "ACTIVATED", h)
        with self.assertRaises(ServiceError):
            self.svc.revoke("base@1")

    def test_override_hits_only_target_region_and_supersedes(self):
        self.svc.publish(scope="policy", content="p1")
        plan_cn = self.svc.pull("cn1", "cn", {})
        plan_eu = self.svc.pull("eu1", "eu", {})
        self.assertEqual(len(plan_cn["ops"]), 1)
        h = plan_cn["ops"][0]["content_sha256"]
        for i, st in enumerate(("DOWNLOADED", "VERIFIED", "ACTIVATED"), 1):
            self.svc.receipt("cn1", "cn", i, "policy@1", st, h)
        for i, st in enumerate(("DOWNLOADED", "VERIFIED", "ACTIVATED"), 1):
            self.svc.receipt("eu1", "eu", i, "policy@1", st, h)

        ov = self.svc.publish(scope="policy", content="EMERGENCY",
                              override=True, target_regions=["cn"])
        plan_cn2 = self.svc.pull("cn1", "cn", {"policy@1": "ACTIVATED"})
        plan_eu2 = self.svc.pull("eu1", "eu", {"policy@1": "ACTIVATED"})
        self.assertEqual([o["version_id"] for o in plan_cn2["ops"]],
                         [ov["version_id"]])
        self.assertEqual(plan_eu2["ops"], [])  # EU 不受影响

        # cn 节点激活覆盖版本
        oh = ov["content_sha256"]
        seq0 = self.svc.store.get_node("cn1")["hw_seq"]
        for i, st in enumerate(("DOWNLOADED", "VERIFIED", "ACTIVATED"), 1):
            self.svc.receipt("cn1", "cn", seq0 + i, ov["version_id"], st, oh)
        states = self.svc.store.node_states("cn1")
        self.assertEqual(states["policy@1"], "SUPERSEDED")
        states_eu = self.svc.store.node_states("eu1")
        self.assertEqual(states_eu["policy@1"], "ACTIVATED")

    def test_late_node_gets_full_chain_after_revoke_and_override(self):
        self.svc.ensure_scope("base")
        self.svc.ensure_scope("policy", parent="base")
        self.svc.publish(scope="base", content="b1")
        b2 = self.svc.publish(scope="base", content="b2")
        self.svc.revoke(b2["version_id"])          # 未扩散先撤销
        b3 = self.svc.publish(scope="base", content="b3")
        self.svc.publish(scope="policy", content="p1",
                         deps={"base": b3["version_id"]})
        plan = self.svc.pull("late", "cn", {})
        vids = [(o["type"], o["version_id"]) for o in plan["ops"]]
        self.assertEqual(vids, [("APPLY", "base@1"), ("APPLY", "base@3"),
                                ("APPLY", "policy@1")])


if __name__ == "__main__":
    unittest.main()
