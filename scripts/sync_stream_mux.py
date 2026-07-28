#!/usr/bin/env python3
from pathlib import Path

src = Path("/mnt/d/Code/idrto/agent/crates/idr-protocol/src/stream_mux.rs").read_text()
out = src.replace("use crate::errors::", "use crate::protocol::errors::")
out = out.replace("use crate::MAX_FRAME_BYTES;", "use crate::protocol::MAX_FRAME_BYTES;")
for dest in (
    "/mnt/d/Code/idrto/presence/src/protocol/stream_mux.rs",
    "/mnt/d/Code/idrto/relay/src/protocol/stream_mux.rs",
):
    Path(dest).write_text(out)
    print("wrote", dest)
