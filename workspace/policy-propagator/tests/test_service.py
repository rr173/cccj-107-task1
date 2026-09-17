"""In-process tests of the control-plane state machine (stdlib unittest)."""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, service  # noqa: E402

TMP = tempfile.mkdtemp(prefix="pptest-")
os.environ["PP_BLOB_DIR"] = os.path.join(TMP, "blobs")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def setUpModule():
    db.init_db(":memory:")
    os.makedirs(os.environ["PP_BLOB_DIR"], exist_ok=True)


def reset():
    db.init_db(":memory:")


def reg(nid, region):
    return service.register_node(nid, region)


def pub(scope, text, kind="base", regions=None, requires=None):
    return service.publish({"scope": scope, "kind": kind,
                            "content_b64": b64(text),
                            "regions": regions, "requires": requires})


def poll(nid, versions=None, active=None):
    return service.poll(nid, {"versions": versions or [],
                              "active": active or {}})


def rcp(nid, vid, state, epoch, sha=None, rid=None):
    import uuid
    return service.receipt(nid, {"receipt_id": rid or str(uuid.uuid4()),
                                 "version": vid, "state": state,
                                 "epoch": epoch, "content_sha": sha})


class TestPublishAndGate(unittest.TestCase):
    def setUp(self):
        reset()

    def test_base_chain_and_dependency_gate(self):
        pub("firmware", "f1")
        fw2 = pub("policy", "p1", requires=["firmware-v1"])
        reg("n-us", "us")
        pl = poll("n-us")
        ids = [x["version"] for x in pl["plan"]]
        self.assertEqual(ids, ["firmware-v1", "policy-v1"])
        # walk policy up to VERIFIED without activating the parent
        psha = db.version("policy-v1")["content_sha"]
        self.assertTrue(rcp("n-us", "policy-v1", "DOWNLOADED", 1, psha)
                        ["accepted"])
        self.assertTrue(rcp("n-us", "policy-v1", "VERIFIED", 1, psha)
                        ["accepted"])
        # activate policy before parent -> gate closed
        self.assertIn("gate closed",
                      rcp("n-us", fw2["id"], "ACTIVATED", 1)["reason"])
        # walk firmware through
        sha = db.version("firmware-v1")["content_sha"]
        self.assertTrue(rcp("n-us", "firmware-v1", "DOWNLOADED", 1, sha)
                        ["accepted"])
        self.assertTrue(rcp("n-us", "firmware-v1", "VERIFIED", 1, sha)
                        ["accepted"])
        self.assertTrue(rcp("n-us", "firmware-v1", "ACTIVATED", 1)
                        ["accepted"])
        # gate now open
        self.assertTrue(rcp("n-us", "policy-v1", "ACTIVATED", 1)
                        ["accepted"])
        self.assertEqual(
            service.get_node("n-us")["versions"].__len__(), 2)

    def test_nonlinear_append_rejected(self):
        a = pub("s", "a")
        pub("s", "b")
        with self.assertRaises(service.DomainError) as e:
            service.publish({"scope": "s", "content_b64": b64("c"),
                             "parent": a["id"]})
        self.assertEqual(e.exception.status, 409)

    def test_unknown_and_revoked_requires_rejected(self):
        pub("s", "a")
        with self.assertRaises(service.DomainError):
            pub("t", "x", requires=["s-v9"])
        with self.assertRaises(service.DomainError):
            service.publish({"scope": "u", "content_b64": b64("z"),
                             "requires": ["s-v1", "s-v1"]})
        # valid dependency publishes; later revoking it blocks new dependents
        pub("t", "x", requires=["s-v1"])
        reg("n", "r")
        poll("n")
        sha = db.version("s-v1")["content_sha"]
        rcp("n", "s-v1", "DOWNLOADED", 1, sha)
        rcp("n", "s-v1", "VERIFIED", 1, sha)
        rcp("n", "s-v1", "ACTIVATED", 1)
        with self.assertRaises(service.DomainError):
            service.revoke("s-v1")  # cannot: t-v1 depends on it too


class TestSafeChain(unittest.TestCase):
    def setUp(self):
        reset()

    def test_offline_node_gets_ordered_chain_not_snapshot(self):
        pub("s", "a")
        reg("n", "r")
        poll("n")
        sha1 = db.version("s-v1")["content_sha"]
        rcp("n", "s-v1", "DOWNLOADED", 1, sha1)
        rcp("n", "s-v1", "VERIFIED", 1, sha1)
        rcp("n", "s-v1", "ACTIVATED", 1)
        # node goes offline; control keeps moving
        pub("s", "b")
        pub("s", "c")
        pl = poll("n", [{"version": "s-v1", "state": "ACTIVATED"}],
                  {"s": "s-v1"})
        self.assertEqual([x["version"] for x in pl["plan"]],
                         ["s-v2", "s-v3"])
        # chain is ordered parent-first for activation
        self.assertEqual(pl["plan"][1]["parent"], "s-v2")

    def test_divergent_baseline_refused(self):
        # Fabricate a node that claims an active version not on the line.
        pub("s", "a")
        reg("n", "r")
        from app import states
        # Create an orphan version row directly to simulate a foreign baseline
        import datetime
        db.conn().execute(
            "INSERT INTO versions(id,scope,seq,kind,parent,requires,regions,"
            "content_sha,size_bytes,revoked,created_at) VALUES("
            "'alien-v0','s',0,'base',NULL,'[]',NULL,'x',1,0,?)",
            (service.now(),))
        with self.assertRaises(service.DomainError) as e:
            poll("n", [{"version": "alien-v0", "state": "ACTIVATED"}],
                 {"s": "alien-v0"})
        self.assertIn("not an ancestor", str(e.exception))


class TestRevoke(unittest.TestCase):
    def setUp(self):
        reset()

    def test_revoke_before_activation_purges_everywhere(self):
        pub("s", "a")
        v2 = pub("s", "b")
        reg("n", "r")
        poll("n")
        sha = v2["content_sha"]
        rcp("n", "s-v2", "DOWNLOADED", 1, sha)
        out = service.revoke("s-v2")
        self.assertEqual(out["inflight_nodes_invalidated"], 1)
        pl = poll("n", [{"version": "s-v2", "state": "DOWNLOADED"}])
        self.assertEqual(pl["purge"],
                         [{"version": "s-v2", "epoch": 2}])
        # stale pre-revoke receipt fenced / refused
        bad = rcp("n", "s-v2", "VERIFIED", 1, sha)
        self.assertFalse(bad["accepted"])
        # same-state stale ack must also be fenced
        bad2 = rcp("n", "s-v2", "PURGED", 1)
        self.assertFalse(bad2["accepted"])
        self.assertIn("fenced", bad2["reason"])
        # purge ack with new epoch works
        ok = rcp("n", "s-v2", "PURGED", 2)
        self.assertTrue(ok["accepted"])

    def test_revoke_after_activation_refused(self):
        pub("s", "a")
        reg("n", "r")
        poll("n")
        sha = db.version("s-v1")["content_sha"]
        rcp("n", "s-v1", "DOWNLOADED", 1, sha)
        rcp("n", "s-v1", "VERIFIED", 1, sha)
        rcp("n", "s-v1", "ACTIVATED", 1)
        with self.assertRaises(service.DomainError) as e:
            service.revoke("s-v1")
        self.assertIn("already active", str(e.exception))


class TestReceipts(unittest.TestCase):
    def setUp(self):
        reset()
        pub("s", "a")
        reg("n", "r")
        poll("n")

    def _sha(self):
        return db.version("s-v1")["content_sha"]

    def test_duplicate_replays_verdict(self):
        rid = "fixed-id"
        a = rcp("n", "s-v1", "DOWNLOADED", 1, self._sha(), rid=rid)
        b = rcp("n", "s-v1", "DOWNLOADED", 1, self._sha(), rid=rid)
        self.assertTrue(a["accepted"])
        self.assertTrue(b["accepted"])
        self.assertTrue(b["duplicate"])

    def test_reorder_and_skip_refused(self):
        # VERIFIED without DOWNLOADED
        self.assertFalse(
            rcp("n", "s-v1", "VERIFIED", 1, self._sha())["accepted"])
        rcp("n", "s-v1", "DOWNLOADED", 1, self._sha())
        # ACTIVATED skips VERIFIED
        out = rcp("n", "s-v1", "ACTIVATED", 1)
        self.assertFalse(out["accepted"])
        self.assertIn("out of order", out["reason"])

    def test_bad_hash_refused(self):
        out = rcp("n", "s-v1", "DOWNLOADED", 1, "deadbeef")
        self.assertTrue(out["accepted"])  # download claim is just a claim
        out = rcp("n", "s-v1", "VERIFIED", 1, "deadbeef")
        self.assertFalse(out["accepted"])
        self.assertIn("hash mismatch", out["reason"])

    def test_old_receipt_cannot_move_backwards(self):
        sha = self._sha()
        rcp("n", "s-v1", "DOWNLOADED", 1, sha)
        rcp("n", "s-v1", "VERIFIED", 1, sha)
        out = rcp("n", "s-v1", "DOWNLOADED", 1, sha)
        self.assertFalse(out["accepted"])
        self.assertIn("backwards", out["reason"])

    def test_epoch_fence(self):
        # bump epoch server-side by direct re-arm, then use old epoch
        db.conn().execute(
            "UPDATE node_versions SET epoch=3 WHERE node_id='n'"
            " AND version_id='s-v1'")
        out = rcp("n", "s-v1", "DOWNLOADED", 1, self._sha())
        self.assertFalse(out["accepted"])
        self.assertIn("stale epoch", out["reason"])


class TestOverrides(unittest.TestCase):
    def setUp(self):
        reset()
        pub("s", "a")
        reg("eu", "eu")
        reg("us", "us")
        poll("eu")
        poll("us")
        for nid in ("eu", "us"):
            sha = db.version("s-v1")["content_sha"]
            rcp(nid, "s-v1", "DOWNLOADED", 1, sha)
            rcp(nid, "s-v1", "VERIFIED", 1, sha)
            rcp(nid, "s-v1", "ACTIVATED", 1)

    def test_region_scoped_override_only_targets_region(self):
        ov = pub("s", "HOTFIX", kind="override", regions=["eu"])
        self.assertEqual(ov["id"], "s-v2")
        pe = poll("eu", [{"version": "s-v1", "state": "ACTIVATED"}],
                  {"s": "s-v1"})
        pu = poll("us", [{"version": "s-v1", "state": "ACTIVATED"}],
                  {"s": "s-v1"})
        self.assertEqual([x["version"] for x in pe["plan"]], ["s-v2"])
        self.assertEqual(pu["plan"], [])
        self.assertEqual(pe["desired"]["s"], "s-v2")
        self.assertEqual(pu["desired"]["s"], "s-v1")

    def test_override_activation_marks_old_overridden(self):
        pub("s", "HOTFIX", kind="override", regions=["eu"])
        poll("eu", [{"version": "s-v1", "state": "ACTIVATED"}],
             {"s": "s-v1"})
        sha = db.version("s-v2")["content_sha"]
        rcp("eu", "s-v2", "DOWNLOADED", 1, sha)
        rcp("eu", "s-v2", "VERIFIED", 1, sha)
        rcp("eu", "s-v2", "ACTIVATED", 1)
        view = {v["version"]: v["state"]
                for v in service.get_node("eu")["versions"]}
        self.assertEqual(view["s-v1"], "OVERRIDDEN")
        self.assertEqual(view["s-v2"], "ACTIVATED")
        # a late ACTIVATED for the old version is now fenced (epoch bumped)
        late = rcp("eu", "s-v1", "ACTIVATED", 1)
        self.assertFalse(late["accepted"])

    def test_override_requires_region_filter(self):
        with self.assertRaises(service.DomainError):
            pub("s", "x", kind="override")

    def test_new_base_does_not_retire_live_override(self):
        pub("s", "HOT", kind="override", regions=["eu"])
        pub("s", "b")  # main line moves
        pe = poll("eu", [{"version": "s-v1", "state": "ACTIVATED"}],
                  {"s": "s-v1"})
        # desired stays the override
        self.assertEqual(pe["desired"]["s"], "s-v2")


class TestBlob(unittest.TestCase):
    def setUp(self):
        reset()

    def test_blob_roundtrip_and_revoked_404(self):
        pub("s", "payload")
        self.assertEqual(service.blob_bytes("s-v1"), b"payload")
        reg("n", "r")
        poll("n")
        service.revoke("s-v1")
        with self.assertRaises(service.DomainError) as e:
            service.blob_bytes("s-v1")
        self.assertEqual(e.exception.status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
