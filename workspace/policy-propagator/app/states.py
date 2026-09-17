"""Domain constants: receipt states and ordering.

State of one (node, version) pair is a monotone ladder. The control side
refuses any receipt that would move it downwards or skip a rung, and uses an
`epoch` fence so that stale in-flight receipts invalidated by a server-side
decision (revoke / re-delivery) are rejected too.
"""

# Ranking is the core invariant: progress can never move to a smaller rank.
STATE_RANK = {
    "PENDING": 0,      # intent exists, node never obtained the blob
    "DOWNLOADED": 1,   # node fetched bytes (sha256 announced by node)
    "VERIFIED": 2,     # node re-hashed and content matches control digest
    "ACTIVATED": 3,    # live on the node, dependency gate passed
    "OVERRIDDEN": 4,   # was active; a newer version in the same scope replaced it
    "PURGED": 5,       # version revoked before activation; node deleted its copy
}

RANK_STATE = {v: k for k, v in STATE_RANK.items()}

# Rungs that count as "the required content has safely arrived at this node"
# for dependency-gate purposes. OVERRIDDEN counts: when a parent scope moved
# further, an older required version was still applied at some point.
ARRIVED_STATES = {"ACTIVATED", "OVERRIDDEN"}

TERMINAL_STATES = {"OVERRIDDEN", "PURGED"}

VALID_KINDS = ("base", "override")
