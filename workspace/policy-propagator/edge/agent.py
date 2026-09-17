"""Edge-node agent (pure stdlib).

Responsibilities:
  * register with the control plane and long-poll periodically;
  * advance strictly along the ordered update chain: download -> verify ->
    activate, checking the dependency gate locally before activating;
  * persist every receipt and retry it with a STABLE receipt_id, so network
    duplicates are idempotent on the control side;
  * honour purge directives for revoked versions;
  * expose an admin port so a test/demo can sever its link ("offline"),
    freeze processing, trigger a single poll, or inject raw receipts.
"""
import hashlib
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

NODE_ID = os.environ["NODE_ID"]
REGION = os.environ["REGION"]
CONTROL = os.environ.get("CONTROL_URL", "http://control:8080").rstrip("/")
STATE_DIR = os.environ.get("STATE_DIR", "/data")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "2"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "9000"))

STATE_FILE = os.path.join(STATE_DIR, "state.json")
BLOB_DIR = os.path.join(STATE_DIR, "blobs")
ACTIVE_DIR = os.path.join(STATE_DIR, "active")

# mutable runtime mode (not persisted; starts healthy)
MODE = {"offline": False, "frozen": False}
LAST_POLL = {}


def log(msg):
    print(f"[{NODE_ID}] {msg}", flush=True)


# ----------------------------------------------------------- persistence ---

def load_state():
    os.makedirs(BLOB_DIR, exist_ok=True)
    os.makedirs(ACTIVE_DIR, exist_ok=True)
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            s = json.load(f)
        s.setdefault("versions", {})
        s.setdefault("active", {})
        s.setdefault("queue", [])
        return s
    return {"versions": {}, "active": {}, "queue": []}


STATE = load_state()


def save_state():
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(STATE, f, indent=1, sort_keys=True)
    os.replace(tmp, STATE_FILE)


# ----------------------------------------------------------------- http ----

def http_json(method, path, obj=None, timeout=10):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urlrequest.Request(
        CONTROL + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    with urlrequest.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def http_get_blob(path, timeout=30):
    with urlrequest.urlopen(CONTROL + path, timeout=timeout) as r:
        return r.read()


# ------------------------------------------------------------- receipts ----

def enqueue_receipt(vid, claimed, epoch, sha=None):
    rid = str(uuid.uuid4())
    STATE["queue"].append({"receipt_id": rid, "version": vid,
                           "state": claimed, "epoch": epoch,
                           "content_sha": sha})
    save_state()
    log(f"receipt queued: {claimed} {vid} (epoch {epoch}) id={rid[:8]}")


def flush_queue():
    if MODE["offline"]:
        return
    remaining = []
    for rcp in STATE["queue"]:
        try:
            res = http_json("POST", f"/nodes/{NODE_ID}/receipts", rcp)
            if not res.get("accepted") and "stale" not in res.get("reason", ""):
                log(f"receipt rejected, dropping: {res.get('reason')}")
            elif res.get("duplicate"):
                log("duplicate receipt acknowledged by control")
            # accepted or stale-fence -> done either way
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            log(f"receipt send failed (will retry): {e}")
            remaining.append(rcp)
    STATE["queue"] = remaining
    save_state()


# --------------------------------------------------------------- actions ---

def blob_path(vid):
    return os.path.join(BLOB_DIR, vid)


def apply_purge(p):
    vid, epoch = p["version"], p["epoch"]
    try:
        os.remove(blob_path(vid))
    except FileNotFoundError:
        pass
    if STATE["active"].get(STATE["versions"].get(vid, {}).get("scope", "")) \
            == vid:
        STATE["active"] = {s: v for s, v in STATE["active"].items()
                           if v != vid}
    STATE["versions"][vid] = {"state": "PURGED"}
    enqueue_receipt(vid, "PURGED", epoch)
    save_state()
    log(f"purged revoked {vid}")


def apply_item(it):
    """Advise one chain item one or more rungs; stop when blocked."""
    vid = it["version"]
    local = STATE["versions"].get(vid, {}).get("state", "PENDING")
    if local in ("ACTIVATED", "OVERRIDDEN", "PURGED"):
        return
    epoch = it["epoch"]

    # 1) download ----------------------------------------------------------
    if local == "PENDING":
        path = blob_path(vid)
        if not os.path.exists(path):
            data = http_get_blob(it["blob_url"])
            with open(path, "wb") as f:
                f.write(data)
        sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
        STATE["versions"][vid] = {"state": "DOWNLOADED", "sha": sha,
                                  "scope": it["scope"]}
        enqueue_receipt(vid, "DOWNLOADED", epoch, sha)
        save_state()
        local = "DOWNLOADED"

    # 2) verify ------------------------------------------------------------
    if local == "DOWNLOADED":
        sha = STATE["versions"][vid]["sha"]
        if sha != it["content_sha"]:
            log(f"VERIFY FAILED {vid}: {sha} != {it['content_sha']}")
            return
        STATE["versions"][vid]["state"] = "VERIFIED"
        enqueue_receipt(vid, "VERIFIED", epoch, sha)
        save_state()
        local = "VERIFIED"

    # 3) activate (dependency gate checked locally) ------------------------
    if local == "VERIFIED":
        for dep in [it["parent"]] + it["requires"]:
            if dep is None:
                continue
            ds = STATE["versions"].get(dep, {}).get("state")
            if ds not in ("ACTIVATED", "OVERRIDDEN"):
                log(f"gate closed for {vid}: dependency {dep} is {ds},"
                    " waiting for next poll")
                return
        scope = it["scope"]
        old = STATE["active"].get(scope)
        payload = open(blob_path(vid), "rb").read()
        final = os.path.join(ACTIVE_DIR, f"{scope}.conf")
        tmp = final + ".tmp"
        with open(tmp, "wb") as f:
            f.write(payload)
        os.replace(tmp, final)
        STATE["versions"][vid]["state"] = "ACTIVATED"
        STATE["active"][scope] = vid
        if old and old != vid:
            # control flips the old active version to OVERRIDDEN itself when
            # it processes this ACTIVATED receipt (and bumps its epoch), so
            # no separate OVERRIDDEN receipt is sent.
            STATE["versions"][old]["state"] = "OVERRIDDEN"
        enqueue_receipt(vid, "ACTIVATED", epoch)
        save_state()
        log(f"ACTIVATED {vid} in scope {scope}"
            + (f" (supersedes {old})" if old else ""))


def report_body():
    return {"versions": [{"version": v, "state": d["state"]}
                         for v, d in STATE["versions"].items()],
            "active": STATE["active"]}


def one_cycle(force=False):
    if MODE["offline"]:
        return
    try:
        res = http_json("POST", f"/nodes/{NODE_ID}/poll", report_body())
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        log(f"poll failed: {e}")
        return
    global LAST_POLL
    LAST_POLL = res
    log(f"poll: desired={res.get('desired')} plan={[x['version'] for x in res.get('plan', [])]}"
        f" purge={[x['version'] for x in res.get('purge', [])]}")
    flush_queue()
    if MODE["frozen"] and not force:
        log("frozen: plan not applied")
        return
    for p in res.get("purge", []):
        apply_purge(p)
    for it in res.get("plan", []):
        local = STATE["versions"].get(it["version"], {}).get("state")
        if local in ("ACTIVATED", "OVERRIDDEN"):
            continue
        apply_item(it)
        flush_queue()


# -------------------------------------------------------------- admin ----

class AdminHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/state":
            return self._send(200, {"node": NODE_ID, "region": REGION,
                                    "mode": MODE, "state": STATE,
                                    "last_poll": LAST_POLL})
        if self.path == "/active":
            files = {}
            for fn in sorted(os.listdir(ACTIVE_DIR)):
                files[fn] = open(os.path.join(ACTIVE_DIR, fn), "rb")\
                    .read().decode(errors="replace")
            return self._send(200, files)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/mode":
            MODE["offline"] = bool(body.get("offline", MODE["offline"]))
            MODE["frozen"] = bool(body.get("frozen", MODE["frozen"]))
            log(f"mode -> {MODE}")
            return self._send(200, MODE)
        if self.path == "/poll":
            one_cycle(force=True)
            return self._send(200, LAST_POLL)
        if self.path == "/flush":
            flush_queue()
            return self._send(200, {"queue": STATE["queue"]})
        if self.path == "/send-receipt":
            # raw injection: test duplicated / reordered / stale receipts
            rcp = {"receipt_id": body.get("receipt_id") or str(uuid.uuid4()),
                   "version": body["version"], "state": body["state"],
                   "epoch": body.get("epoch"),
                   "content_sha": body.get("content_sha")}
            try:
                res = http_json("POST",
                                f"/nodes/{NODE_ID}/receipts", rcp)
            except HTTPError as e:
                res = {"http_error": e.code, **json.loads(e.read())}
            return self._send(200, res)
        self._send(404, {"error": "not found"})


# ----------------------------------------------------------------- main ----

def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    admin = ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), AdminHandler)
    import threading
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    log(f"agent starting region={REGION} control={CONTROL}")

    while True:
        try:
            if not MODE["offline"]:
                http_json("POST", "/nodes",
                          {"node_id": NODE_ID, "region": REGION})
                one_cycle()
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            log(f"control unreachable: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
