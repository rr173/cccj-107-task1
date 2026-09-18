"""核心领域逻辑测试：依赖闸门、安全更新链、紧急覆盖、回执防倒退、撤销闸门。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from core import (ACTIVATED, APPLY, DOWNLOADED, RECALL, REPLACED, REVOKED,
                  SUPERSEDED, VERIFIED, ChainOp, Version, can_revoke,
                  decide_receipt, plan_chain)


def mk(vid, deps=None, override=False, regions=None, nodes=None, revoked=False,
       content="c"):
    scope, seq = vid.rsplit("@", 1)
    return Version(id=vid, scope=scope, seq=int(seq), content=content,
                   content_sha256="h-" + content, deps=deps or {},
                   override=override, target_regions=regions or [],
                   target_nodes=nodes or [], revoked=revoked)


def ids(ops):
    return [(o.type, o.version.id) for o in ops]


class TestPlanChain(unittest.TestCase):
    def test_parent_before_child_and_ordered_within_scope(self):
        versions = [
            mk("base@1"),
            mk("base@2"),
            mk("policy@1", deps={"base": "base@1"}),
            mk("policy@2", deps={"base": "base@2"}),
        ]
        plan = plan_chain(versions, "n1", "cn", {})
        # 全新节点必须按链前进：base@1 -> base@2 -> policy@1(依赖base@1) -> policy@2
        self.assertEqual(ids(plan.ops),
                         [("APPLY", "base@1"), ("APPLY", "base@2"),
                          ("APPLY", "policy@1"), ("APPLY", "policy@2")])

    def test_resumes_from_local_version_not_latest_snapshot(self):
        versions = [mk("base@1"), mk("base@2"), mk("base@3")]
        # 长离线后本地只到 @1 且已激活：链从 @2 续上，不能直接发 @3
        plan = plan_chain(versions, "n1", "cn", {"base@1": ACTIVATED})
        self.assertEqual(ids(plan.ops),
                         [("APPLY", "base@2"), ("APPLY", "base@3")])

    def test_half_done_child_waits_for_parent(self):
        versions = [
            mk("base@1"),
            mk("policy@1", deps={"base": "base@1"}),
        ]
        # policy@1 已下载但 base 尚未激活：链先给 base@1，再给 policy@1；
        # 代理顺序执行时父版本先激活，子版本随后通过闸门 —— 安全前进。
        plan = plan_chain(versions, "n1", "cn", {"policy@1": DOWNLOADED})
        self.assertEqual(ids(plan.ops),
                         [("APPLY", "base@1"), ("APPLY", "policy@1")])

        # 若控制端观测到父版本已激活，直接返回 policy@1
        plan2 = plan_chain(versions, "n1", "cn",
                           {"policy@1": DOWNLOADED, "base@1": ACTIVATED})
        self.assertEqual(ids(plan2.ops), [("APPLY", "policy@1")])

    def test_override_targets_only_selected_region(self):
        versions = [
            mk("policy@1"),
            mk("policy@2", override=True, regions=["cn"]),
        ]
        cn = plan_chain(versions, "cn-node", "cn", {"policy@1": ACTIVATED})
        eu = plan_chain(versions, "eu-node", "eu", {"policy@1": ACTIVATED})
        self.assertEqual(ids(cn.ops), [("APPLY", "policy@2")])
        self.assertEqual(ids(eu.ops), [])  # EU 节点不领取紧急覆盖

    def test_override_chain_on_reconnect(self):
        # 长离线的 cn 节点只有 @1；@2/@3 是普通版，@4 是 cn 紧急覆盖。
        # 链必须把 @4 排在 @2/@3 之后（覆盖基于最新内容），中间版本不跳过。
        versions = [mk("policy@1"), mk("policy@2"), mk("policy@3"),
                    mk("policy@4", override=True, regions=["cn"])]
        plan = plan_chain(versions, "cn-late", "cn", {"policy@1": ACTIVATED})
        self.assertEqual(ids(plan.ops), [("APPLY", "policy@2"),
                                         ("APPLY", "policy@3"),
                                         ("APPLY", "policy@4")])

    def test_revoked_versions_recalled_and_skipped(self):
        versions = [mk("base@1"), mk("base@2", revoked=True),
                    mk("base@3", deps={})]
        plan = plan_chain(versions, "n1", "cn",
                          {"base@2": DOWNLOADED, "base@1": ACTIVATED})
        self.assertEqual(ids(plan.ops),
                         [("RECALL", "base@2"), ("APPLY", "base@3")])

    def test_child_blocked_when_dependency_revoked(self):
        versions = [
            mk("base@1", revoked=True),
            mk("policy@1", deps={"base": "base@1"}),
        ]
        plan = plan_chain(versions, "n1", "cn", {})
        # 已撤销的 base@1 不进链；policy@1 依赖它 -> 永久阻塞
        self.assertEqual(ids(plan.ops), [])
        blocked_ids = {b["version_id"] for b in plan.blocked}
        self.assertNotIn("base@1", ids(plan.ops))
        self.assertIn("policy@1", blocked_ids)
        self.assertTrue(next(b for b in plan.blocked
                             if b["version_id"] == "policy@1")["permanent"])


class TestReceipt(unittest.TestCase):
    def setUp(self):
        self.v = {"base@1": mk("base@1", content="c"),
                  "base@2": mk("base@2", content="c2")}

    def decide(self, **kw):
        defaults = dict(
            claimed_version_id="base@1", claimed_state=DOWNLOADED, seq=1,
            sha256="h-c", high_water=0, last_seq=None, last_version_id=None,
            last_state=None, node_states={}, versions=self.v,
            active_versions_by_scope={})
        defaults.update(kw)
        return decide_receipt(**defaults)

    def test_happy_path(self):
        d = self.decide()
        self.assertTrue(d.accepted, d.reason)
        self.assertEqual(d.new_state, DOWNLOADED)

        d2 = self.decide(claimed_state=VERIFIED, seq=2, high_water=1,
                         last_seq=1, last_version_id="base@1",
                         last_state=DOWNLOADED,
                         node_states={"base@1": DOWNLOADED}, sha256="h-c")
        self.assertTrue(d2.accepted, d2.reason)

    def test_stale_and_gap_rejected(self):
        self.assertTrue(self.decide(seq=1).accepted)
        stale = self.decide(seq=1, high_water=5)
        self.assertFalse(stale.accepted)
        self.assertIn("stale", stale.reason)
        gap = self.decide(seq=3, high_water=1)
        self.assertFalse(gap.accepted)
        self.assertIn("gap", gap.reason)

    def test_exact_duplicate_is_idempotent(self):
        d = self.decide(seq=1, high_water=1, last_seq=1,
                        last_version_id="base@1", last_state=DOWNLOADED)
        self.assertTrue(d.accepted)
        self.assertIn("duplicate", d.reason)
        # 同 seq 但内容不同 -> 视为乱序/重影攻击，拒绝
        d2 = self.decide(seq=1, claimed_version_id="base@2",
                         sha256="h-c2", high_water=1, last_seq=1,
                         last_version_id="base@1", last_state=DOWNLOADED)
        self.assertFalse(d2.accepted)

    def test_regression_blocked(self):
        # VERIFIED 之后想退回 DOWNLOADED
        d = self.decide(claimed_state=DOWNLOADED, seq=2, high_water=1,
                        node_states={"base@1": VERIFIED})
        self.assertFalse(d.accepted)

    def test_hash_mismatch_blocked(self):
        d = self.decide(sha256="wrong")
        self.assertFalse(d.accepted)
        self.assertIn("sha256", d.reason)

    def test_activation_requires_active_parent(self):
        versions = dict(self.v)
        versions["policy@1"] = mk("policy@1", deps={"base": "base@1"})
        d = decide_receipt(
            claimed_version_id="policy@1", claimed_state=ACTIVATED, seq=1,
            sha256="h-c", high_water=0, last_seq=None, last_version_id=None,
            last_state=None, node_states={"policy@1": VERIFIED},
            versions=versions, active_versions_by_scope={})
        self.assertFalse(d.accepted)
        self.assertIn("never reached", d.reason)

        d2 = decide_receipt(
            claimed_version_id="policy@1", claimed_state=ACTIVATED, seq=1,
            sha256="h-c", high_water=0, last_seq=None, last_version_id=None,
            last_state=None,
            node_states={"policy@1": VERIFIED, "base@1": ACTIVATED},
            versions=versions,
            active_versions_by_scope={"base": ["base@1"]})
        self.assertTrue(d2.accepted, d2.reason)

    def test_activation_cascades_replaced_and_superseded(self):
        versions = dict(self.v)
        versions["policy@3"] = mk("policy@3")
        versions["policy@9"] = mk("policy@9", override=True, regions=["cn"])
        # 普通升级 -> 旧激活版本 REPLACED
        d = decide_receipt(
            claimed_version_id="base@2", claimed_state=ACTIVATED, seq=1,
            sha256="h-c2", high_water=0, last_seq=None, last_version_id=None,
            last_state=None,
            node_states={"base@1": ACTIVATED, "base@2": VERIFIED},
            versions=versions, active_versions_by_scope={"base": ["base@1"]})
        self.assertTrue(d.accepted)
        self.assertIn(("base@1", REPLACED), d.cascades)

        # 紧急覆盖 -> 旧激活版本 SUPERSEDED
        versions["policy@1"] = mk("policy@1")
        d2 = decide_receipt(
            claimed_version_id="policy@9", claimed_state=ACTIVATED, seq=1,
            sha256="h-c", high_water=0, last_seq=None, last_version_id=None,
            last_state=None,
            node_states={"policy@1": ACTIVATED, "policy@9": VERIFIED},
            versions=versions,
            active_versions_by_scope={"policy": ["policy@1"]})
        self.assertTrue(d2.accepted, d2.reason)
        self.assertIn(("policy@1", SUPERSEDED), d2.cascades)

    def test_revoked_version_rejects_forward_receipts(self):
        self.v["base@1"].revoked = True
        d = self.decide()
        self.assertFalse(d.accepted)
        self.assertIn("revoked", d.reason)


class TestRevokeGate(unittest.TestCase):
    def test_cannot_revoke_after_activation_anywhere(self):
        v = mk("base@1")
        ok, _ = can_revoke(v, {"n1": DOWNLOADED})
        self.assertTrue(ok)
        ok, reason = can_revoke(v, {"n1": ACTIVATED})
        self.assertFalse(ok)
        ok2, _ = can_revoke(v, {"n1": SUPERSEDED})
        self.assertFalse(ok2)


if __name__ == "__main__":
    unittest.main()
