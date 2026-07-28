#!/usr/bin/env python3
from pathlib import Path

agent = Path("/mnt/d/Code/idrto/agent")

# Protocol crate: crate::protocol:: -> crate::
for p in (agent / "crates/idr-protocol/src").rglob("*.rs"):
    t = p.read_text(encoding="utf-8")
    n = t.replace("crate::protocol::", "crate::")
    if n != t:
        p.write_text(n, encoding="utf-8")
        print("proto", p.name)

proto_src = agent / "crates/idr-protocol/src"
print("protocol files:", sorted(x.name for x in proto_src.iterdir()))

if not (proto_src / "lib.rs").exists():
    if (proto_src / "mod.rs").exists():
        (proto_src / "mod.rs").rename(proto_src / "lib.rs")
        print("renamed mod.rs -> lib.rs")
    else:
        raise SystemExit("ERROR: no lib.rs for protocol")

libp = proto_src / "lib.rs"
t = libp.read_text(encoding="utf-8").replace("crate::protocol::", "crate::")
old = "This module is duplicated identically in `target-quic`, `idr-relay`, and `idr-presence`."
new = (
    "Canonical copy lives in the agent monorepo (idr-protocol). "
    "Keep presence and relay copies in sync until they depend on this crate."
)
t = t.replace(old, new)
libp.write_text(t, encoding="utf-8")
print("protocol lib.rs ready")

# Target: crate::protocol:: -> idr_protocol::
for p in (agent / "crates/idr-target/src").rglob("*.rs"):
    t = p.read_text(encoding="utf-8")
    n = t.replace("crate::protocol::", "idr_protocol::")
    n = n.replace("use crate::protocol;", "use idr_protocol;")
    if n != t:
        p.write_text(n, encoding="utf-8")
        print("target", p.relative_to(agent))

(agent / "crates/idr-target/src/lib.rs").write_text(
    """//! IDR Target Agent library (Presence, Relay QUIC, tunnels, ACME, WebRTC answerer).

pub use idr_protocol as protocol;

pub mod config;
pub mod identity;
pub mod network;
pub mod presence;
pub mod quic;
pub mod relay;
pub mod shutdown;
pub mod storage;
pub mod telemetry;
pub mod tunnel;
pub mod acme;
pub mod webrtc;
""",
    encoding="utf-8",
)
print("wrote idr-target lib.rs")

# Service main: target_quic:: -> idr_target::
main = agent / "services/target-agent/src/main.rs"
t = main.read_text(encoding="utf-8")
t = t.replace("target_quic::", "idr_target::")
t = t.replace("use target_quic::", "use idr_target::")
main.write_text(t, encoding="utf-8")
print("rewrote target-agent main")

# mock-presence may use target_quic or crate::
mp = agent / "services/mock-presence/src/main.rs"
t = mp.read_text(encoding="utf-8")
t = t.replace("target_quic::protocol::", "idr_protocol::")
t = t.replace("target_quic::", "idr_protocol::")
mp.write_text(t, encoding="utf-8")
print("rewrote mock-presence")

# Integration tests
for p in (agent / "tests").glob("*.rs"):
    t = p.read_text(encoding="utf-8")
    n = t.replace("target_quic::", "idr_target::")
    n = n.replace("use target_quic", "use idr_target")
    if n != t:
        p.write_text(n, encoding="utf-8")
        print("test", p.name)

# Benches
for p in (agent / "benches").glob("*.rs"):
    t = p.read_text(encoding="utf-8")
    n = t.replace("target_quic::", "idr_target::")
    if n != t:
        p.write_text(n, encoding="utf-8")
        print("bench", p.name)

print("DONE")
