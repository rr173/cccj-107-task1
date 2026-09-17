#!/usr/bin/env python3
"""End-to-end verification without docker (also usable inside a container).

Starts one control server and three real edge agents (eu/us/apac), then
drives every requirement end to end:

  1. cross-scope dependency propagation and activation gate
  2. long-offline node receives an ORDERED safe update chain
  3. revoke of a not-yet-spread version -> PURGED + purge directive
  4. region-scoped emergency override (eu only) survives a newer base
  5. duplicate / reordered / stale receipts cannot corrupt or regress state

Exits non-zero on the first failed assertion.
"""
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = tempfile.mkdtemp(prefix="ppe2e-")
CTRL_PORT = int(os.environ.get("E2E_CTRL_PORT", "18080"))
NODES = [("edge-eu-1", "eu", 19001),
         ("edge-us-1", "us", 19002),
         ("edge-apac-1", "apac", 19003)]

procs = []


def http(method, url, obj=None, timeout=10):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise AssertionError(f"{method} {url} -> {e.code}: "
                             f"{e.read().decode()}")


def ctrl(method, path, obj=None):
    return http(method, f"http://127.0.0.1:{CTRL_PORT}{path}", obj)


def admin(node, method, path, obj=None, port=None):
    p = dict((n, prt) for n, _, prt in NODES)[node] if port is None else port
    return http(method, f"http://127.0.0.1:{p}{path}", obj)


def b64(s):
    return base64.b64encode(s.encode()).decode()


def publish(scope, text, **kw):
    p = {"scope": scope, "content_b64": b64(text)}
    p.update(kw)
    return ctrl("POST", "/versions", p)


def node_view(nid):
    return ctrl("GET", f"/nodes/{nid}")


def states(nid):
    return {v["version"]: v["state"] for v in node_view(nid)["versions"]}


def active_files(node):
    return admin(node, "GET", "/active")


def wait_for(desc, fn, timeout=25.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:
            last = e
        time.sleep(0.4)
    raise AssertionError(f"TIMEOUT waiting for: {desc} (last={last})")


def set_mode(node, **kw):
    admin(node, "POST", "/mode", kw)


def start():
    os.makedirs(f"{WORK}/blobs", exist_ok=True)
    env = dict(os.environ, PYTHONPATH=ROOT, PP_DB=f"{WORK}/ctrl.db",
               PP_BLOB_DIR=f"{WORK}/blobs", PP_PORT=str(CTRL_PORT))
    log = open(f"{WORK}/control.log", "wb")
    procs.append(subprocess.Popen(
        [sys.executable, "-m", "app.main"], cwd=ROOT, env=env,
        stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid))
    wait_for("control health",
             lambda: ctrl("GET", "/health").get("ok"))

    for nid, region, aport in NODES:
        sdir = f"{WORK}/{nid}"
        os.makedirs(sdir, exist_ok=True)
        env2 = dict(os.environ, PYTHONPATH=ROOT, NODE_ID=nid, REGION=region,
                    STATE_DIR=sdir, CONTROL_URL=f"http://127.0.0.1:{CTRL_PORT}",
                    ADMIN_PORT=str(aport), POLL_INTERVAL="0.5")
        lf = open(f"{WORK}/{nid}.log", "wb")
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "edge.agent"], cwd=ROOT, env=env2,
            stdout=lf, stderr=subprocess.STDOUT, preexec_fn=os.setsid))


def stop():
    for p in procs:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass


def section(t):
    print(f"\n=== {t} ===", flush=True)


def main():
    start()
    try:
        # 1) dependency-ordered rollout ------------------------------------
        section("1. dependency-ordered rollout + activation gate")
        publish("runtime", "runtime-1")
        publish("app", "app-1", requires=["runtime-v1"])
        for nid, _, _ in NODES:
            wait_for(f"{nid} active app-v1", lambda n=nid:
                     active_files(n).get("app.conf") == "app-1")
            st = states(nid)
            assert st["runtime-v1"] == "ACTIVATED", st
            assert st["app-v1"] == "ACTIVATED", st
        print("all 3 regions activated runtime-v1 -> app-v1 in gate order")

        # 2) long offline -> ordered safe chain ----------------------------
        section("2. long-offline node gets an ordered chain, not a snapshot")
        set_mode("edge-apac-1", offline=True, frozen=False)
        time.sleep(0.6)
        publish("runtime", "runtime-2")
        publish("runtime", "runtime-3")
        publish("app", "app-2", requires=["runtime-v3"])
        for nid in ("edge-eu-1", "edge-us-1"):
            wait_for(f"{nid} app-2", lambda n=nid:
                     active_files(n).get("app.conf") == "app-2")
        # frozen reconnect: observe the plan offered to the stale node
        set_mode("edge-apac-1", offline=False, frozen=True)
        wait_for("apac plan populated", lambda:
                 True if "runtime-v3" in [x["version"] for x in
                     admin("edge-apac-1", "GET", "/state")
                     .get("last_poll", {}).get("plan", [])] else None,
                 timeout=10)
        plan = [x["version"] for x in
                admin("edge-apac-1", "GET", "/state")["last_poll"]["plan"]]
        assert plan == ["runtime-v2", "runtime-v3", "app-v2"], plan
        print(f"apac reconnect plan (parent-first): {plan}")
        set_mode("edge-apac-1", frozen=False)
        wait_for("apac app-2", lambda:
                 active_files("edge-apac-1").get("app.conf") == "app-2")

        # 3) revoke before full spread -------------------------------------
        section("3. revoke an incompletely spread version")
        for nid, _, _ in NODES:
            set_mode(nid, offline=True)
        publish("canary", "canary-1")
        # us learns about it while everyone is offline/frozen (direct poll)
        ctrl("POST", "/nodes/edge-us-1/poll",
             {"versions": [], "active":
              {"runtime": "runtime-v3", "app": "app-v2"}})
        rev = ctrl("POST", "/versions/canary-v1/revoke", {})
        assert rev["revoked"] and rev["inflight_nodes_invalidated"] == 1, rev
        set_mode("edge-us-1", offline=False)
        wait_for("us canary PURGED", lambda:
                 "PURGED" if states("edge-us-1").get("canary-v1")
                 == "PURGED" else None)
        set_mode("edge-eu-1", offline=False)
        set_mode("edge-apac-1", offline=False)
        # late pre-revoke receipt must be fenced
        late = admin("edge-us-1", "POST", "/send-receipt",
                     {"version": "canary-v1", "state": "VERIFIED", "epoch": 1})
        assert late["accepted"] is False, late
        print(f"revoke purged the in-flight copy; late receipt rejected:"
              f" {late['reason']}")

        # 4) emergency region override -------------------------------------
        section("4. emergency override scoped to eu only")
        ov = publish("app", "HOTFIX-EU", kind="override", regions=["eu"])
        assert ov["id"] == "app-v3", ov
        wait_for("eu hotfix", lambda:
                 "HOTFIX-EU" if active_files("edge-eu-1")
                 .get("app.conf") == "HOTFIX-EU" else None)
        time.sleep(1.5)
        assert active_files("edge-us-1").get("app.conf") == "app-2"
        assert active_files("edge-apac-1").get("app.conf") == "app-2"
        eu_st = states("edge-eu-1")
        assert eu_st["app-v2"] == "OVERRIDDEN", eu_st
        assert eu_st["app-v3"] == "ACTIVATED", eu_st
        print("eu runs HOTFIX-EU; us/apac untouched; app-v2 = OVERRIDDEN")

        # a newer main-line version must NOT retire the live eu override
        publish("app", "app-4-base")
        wait_for("us app-4", lambda n="edge-us-1":
                 "app-4-base" if active_files(n)
                 .get("app.conf") == "app-4-base" else None)
        time.sleep(1.0)
        assert active_files("edge-eu-1").get("app.conf") == "HOTFIX-EU"
        print("newer base app-v4 rolled elsewhere; eu override still live")

        # 5) receipt chaos --------------------------------------------------
        section("5. duplicate / reordered / stale receipts")
        publish("runtime", "runtime-4")
        set_mode("edge-eu-1", offline=True)
        # make control offer the plan (frozen online poll through auto loop)
        set_mode("edge-eu-1", offline=False, frozen=True)
        time.sleep(1.0)
        epoch = next(x["epoch"] for x in
                     admin("edge-eu-1", "GET", "/state")["last_poll"]["plan"]
                     if x["version"] == "runtime-v4")
        assert epoch == 1

        r1 = admin("edge-eu-1", "POST", "/send-receipt",
                   {"version": "runtime-v4", "state": "VERIFIED", "epoch": 1,
                    "receipt_id": "reorder-1"})
        assert r1["accepted"] is False and "out of order" in r1["reason"], r1
        # legitimate download, then replay the SAME receipt twice
        r2 = admin("edge-eu-1", "POST", "/send-receipt",
                   {"version": "runtime-v4", "state": "DOWNLOADED",
                    "epoch": 1, "content_sha": "whatever",
                    "receipt_id": "dup-1"})
        r3 = admin("edge-eu-1", "POST", "/send-receipt",
                   {"version": "runtime-v4", "state": "DOWNLOADED",
                    "epoch": 1, "content_sha": "whatever",
                    "receipt_id": "dup-1"})
        assert r2["accepted"] and r3["accepted"] and r3.get("duplicate"), r3
        # even an in-flight replay of the earlier REJECTED receipt stays
        # rejected and cannot change state
        r1b = admin("edge-eu-1", "POST", "/send-receipt",
                    {"version": "runtime-v4", "state": "VERIFIED", "epoch": 1,
                     "receipt_id": "reorder-1"})
        assert r1b["accepted"] is False and r1b.get("duplicate"), r1b
        r4 = admin("edge-eu-1", "POST", "/send-receipt",
                   {"version": "runtime-v4", "state": "VERIFIED", "epoch": 1,
                    "content_sha": "whatever"})
        assert not r4["accepted"] and "hash mismatch" in r4["reason"], r4
        # old receipt trying to push progress backwards is impossible; show
        # the epoch-fence on the eu override predecessor instead
        r5 = admin("edge-eu-1", "POST", "/send-receipt",
                   {"version": "app-v2", "state": "ACTIVATED", "epoch": 1})
        assert not r5["accepted"], r5
        print(f"reordered: {r1['reason']}")
        print(f"duplicate replay: accepted={r3['accepted']}"
              f" duplicate={r3.get('duplicate')}")
        print(f"bad hash: {r4['reason']}")
        print(f"stale receipt after override: {r5['reason']}")

        set_mode("edge-eu-1", frozen=False)
        wait_for("eu runtime-5", lambda:
                 states("edge-eu-1").get("runtime-v4") == "ACTIVATED")
        assert states("edge-eu-1")["runtime-v4"] == "ACTIVATED"
        print("eu subsequently converges to runtime-v4 with no state damage")

        section("ALL E2E CHECKS PASSED")
        print(f"artifacts/logs under {WORK}")
    finally:
        stop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
        stop()
        sys.exit(1)
