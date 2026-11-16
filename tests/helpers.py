"""Shared test utilities: temporary projects, fake credentials, and a stub Ollama server."""

from __future__ import annotations

import json
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "examples"


# Fake credentials are assembled at runtime so no secret-shaped literal is committed.
def fake_openai_key() -> str:
    return "sk-" + "proj-" + "Ab12Cd34" * 4


def fake_github_token() -> str:
    return "gh" + "p_" + "Zy98Xw76" * 5


def write_project(root: Path, files: dict[str, str]) -> Path:
    """Create ``files`` (relative path -> dedented content) under ``root``."""
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return root


def rule_ids(findings: Iterable[object]) -> set[str]:
    return {finding.rule_id for finding in findings}  # type: ignore[attr-defined]


def findings_with(findings: Iterable[object], rule_id: str) -> list:
    return [finding for finding in findings if finding.rule_id == rule_id]  # type: ignore[attr-defined]


class TempDirTestCase(unittest.TestCase):
    """Provides ``self.tmp`` (a fresh directory) for each test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()


class StubOllama:
    """A loopback HTTP server that imitates ``POST /api/generate``.

    ``responses`` is a list of ``(status, body)`` pairs served in order; the
    last one repeats. ``body`` may be ``bytes`` or a JSON-serializable object.
    ``delay`` makes every response slow (to exercise timeouts).
    """

    def __init__(self, responses: list[tuple[int, object]], delay: float = 0.0) -> None:
        self.responses = responses
        self.delay = delay
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # keep test output quiet
                pass

            def do_POST(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                stub.requests.append({"path": self.path, "body": json.loads(raw or b"{}")})
                index = min(len(stub.requests), len(stub.responses)) - 1
                status, body = stub.responses[index]
                if stub.delay:
                    time.sleep(stub.delay)
                payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass  # client gave up (timeout test)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._server.block_on_close = False  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> "StubOllama":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


def unused_local_port() -> int:
    """Return a loopback port with nothing listening on it (connection refused)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
