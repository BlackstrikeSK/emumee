"""Verify guest HTTP POST bodies are extracted before broker localhost denial."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


BODIES = {
    "managed_post": '{"safe":"é"}'.encode("utf-8"),
    "winhttp_post_x86": b"harmless WinHTTP body",
    "winhttp_post_x64": b"harmless WinHTTP body",
    "wininet_post_x86": b"harmless WinINet body",
    "wininet_post_x64": b"harmless WinINet body",
}


def verify(root: Path) -> None:
    for fixture, body in BODIES.items():
        summaries = list((root / fixture).glob("*/summary.json"))
        assert len(summaries) == 1, (fixture, "expected one packaged run")
        run_dir = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        broker = json.loads((run_dir / "network-broker.json").read_text(encoding="utf-8"))
        assert summary["status"] == "completed" and not summary.get("errors"), fixture
        assert summary["network_broker_complete"] is True, fixture
        uploads = [item for item in summary["artifacts"] if item["source"] ==
                   "network_request_body"]
        assert len(uploads) == 1, (fixture, uploads)
        upload = uploads[0]
        assert upload["kind"] == "network" and upload["guest_path"].startswith(
            "http://127.0.0.1"), (fixture, upload)
        assert upload["size"] == len(body), fixture
        assert upload["sha256"] == hashlib.sha256(body).hexdigest(), fixture
        assert (run_dir / "artifacts" / upload["file"]).read_bytes() == body, fixture
        attempts = [event for event in broker if event.get("event") == "http_request_attempt"]
        assert len(attempts) == 1, (fixture, attempts)
        assert attempts[0]["method"] == "POST" and attempts[0]["host"] == "127.0.0.1"
        assert attempts[0]["body_size"] == upload["size"], fixture
        assert attempts[0]["body_sha256"] == upload["sha256"], fixture
        assert not any(event.get("event") == "http_request" for event in broker), fixture
        assert broker[-1] == {"event": "broker_closed"}, fixture
        print(f"{fixture}: exact request body extracted; broker denied localhost")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
