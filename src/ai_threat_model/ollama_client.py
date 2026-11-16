"""Minimal, hardened client for a local Ollama server.

Security controls:

* Only ``http``/``https`` URLs are accepted, and only loopback hosts unless the
  caller explicitly opts in to a remote server (scan data would leave the host).
* System proxy settings are ignored so prompts are never routed via a proxy.
* Responses are streamed, each request has an inactivity timeout, transient failures are retried a bounded number
  of times with backoff, and responses are size-capped.
* Errors are raised as :class:`LLMError` with messages that never include the
  prompt (which contains project details).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .errors import LLMError

LOGGER = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"
DEFAULT_TIMEOUT_SECONDS = 300.0
DEFAULT_MAX_OUTPUT_TOKENS = 1024
DEFAULT_CONTEXT_TOKENS = 8192
DEFAULT_MAX_RETRIES = 2
MAX_RETRIES_LIMIT = 5
RETRY_BACKOFF_SECONDS = 2.0
MAX_RESPONSE_BYTES = 1_000_000
_LOOPBACK_NAMES = frozenset({"localhost"})
_RETRYABLE_HTTP_CODES = frozenset({408, 429, 500, 502, 503, 504})


class _TransientLLMError(LLMError):
    """A failure that may succeed on retry (connection error, timeout, 5xx)."""


def validate_base_url(url: str, *, allow_remote: bool = False) -> str:
    """Return a normalized base URL or raise :class:`LLMError` if it is not allowed."""
    try:
        parsed = urlparse(url.strip())
    except ValueError as error:
        raise LLMError(f"Invalid Ollama URL: {error}") from error
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LLMError("Ollama URL must be an http(s) URL with a host, e.g. http://127.0.0.1:11434")
    if parsed.username or parsed.password:
        raise LLMError("Ollama URL must not contain credentials")
    if not allow_remote and not _is_loopback(parsed.hostname):
        raise LLMError(
            f"Refusing to send scan data to non-local host '{parsed.hostname}'. "
            "Use --allow-remote-llm to override."
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class OllamaClient:
    """Calls Ollama's ``/api/generate`` endpoint with streaming.

    ``timeout_seconds`` is an inactivity timeout: the longest wait for the first
    token (prompt processing) or between tokens, not a cap on total time. Total
    generation is bounded by ``max_output_tokens``. ``max_retries`` is the number
    of extra attempts after a transient failure (connection error, timeout, 5xx).
    ``context_tokens`` is sent as ``num_ctx`` so the scan facts are not silently
    truncated by Ollama's small default context window.
    """

    base_url: str = DEFAULT_OLLAMA_URL
    model: str = DEFAULT_OLLAMA_MODEL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    allow_remote: bool = False
    temperature: float = 0.1
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    context_tokens: int = DEFAULT_CONTEXT_TOKENS

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", validate_base_url(self.base_url, allow_remote=self.allow_remote))
        if not self.model or len(self.model) > 200 or any(ch.isspace() for ch in self.model):
            raise LLMError("Invalid Ollama model name")
        if self.timeout_seconds <= 0:
            raise LLMError("Ollama timeout must be positive")
        if not 0 <= self.max_retries <= MAX_RETRIES_LIMIT:
            raise LLMError(f"Ollama retries must be between 0 and {MAX_RETRIES_LIMIT}")

    def generate(self, prompt: str, *, system: str = "") -> str:
        """Return the model's completion for ``prompt``.

        Transient failures (connection errors, timeouts, HTTP 408/429/5xx) are
        retried up to ``max_retries`` times with linear backoff. Other errors
        fail immediately.

        Raises:
            LLMError: If every attempt fails, or on a non-retryable error.
        """
        attempts = self.max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                return self._generate_once(prompt, system)
            except _TransientLLMError as error:
                if attempt == attempts:
                    raise LLMError(f"{error} (gave up after {attempts} attempt(s))") from error
                delay = RETRY_BACKOFF_SECONDS * attempt
                LOGGER.warning("Ollama attempt %d/%d failed: %s; retrying in %.0fs", attempt, attempts, error, delay)
                time.sleep(delay)
        raise LLMError("Ollama request failed")  # unreachable; keeps type checkers satisfied

    def _generate_once(self, prompt: str, system: str) -> str:
        """Perform a single streamed request. Raises _TransientLLMError for retryable failures.

        Streaming matters on CPU-only machines: with ``stream: false`` Ollama sends
        nothing until the whole answer is generated, which can exceed any sensible
        socket timeout. Streamed tokens keep the connection alive, so
        ``timeout_seconds`` only has to cover prompt processing and gaps between tokens.
        """
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": True,
            "options": {"temperature": self.temperature, "num_predict": self.max_output_tokens,
                        "num_ctx": self.context_tokens},
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/generate", data=payload, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/x-ndjson"},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        LOGGER.info("Requesting narrative from Ollama model %s at %s (this can take minutes on CPU)",
                    self.model, self.base_url)
        started = time.monotonic()
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                text = self._read_stream(response)
        except urllib.error.HTTPError as error:
            if error.code in _RETRYABLE_HTTP_CODES:
                raise _TransientLLMError(f"Ollama returned HTTP {error.code}") from error
            hint = " (is the model pulled? run `ollama pull " + self.model + "`)" if error.code == 404 else ""
            raise LLMError(f"Ollama returned HTTP {error.code}{hint}") from error
        except urllib.error.URLError as error:
            raise _TransientLLMError(f"Cannot reach Ollama at {self.base_url}: {error.reason}") from error
        except (TimeoutError, OSError) as error:
            raise _TransientLLMError(
                f"Ollama request failed: {type(error).__name__} (no output for {self.timeout_seconds:.0f}s; "
                "try a larger --ollama-timeout or a smaller model)"
            ) from error
        LOGGER.info("Ollama narrative received in %.0fs", time.monotonic() - started)
        return text

    @staticmethod
    def _read_stream(response: Any) -> str:
        """Concatenate the ``response`` fields of Ollama's NDJSON stream, enforcing the size cap."""
        parts: list[str] = []
        received = 0
        while True:
            line = response.readline(MAX_RESPONSE_BYTES + 1)
            if not line:
                break
            received += len(line)
            if received > MAX_RESPONSE_BYTES:
                raise LLMError("Ollama response exceeded the size limit")
            if not line.strip():
                continue
            try:
                chunk = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise LLMError("Ollama returned a malformed response") from error
            if not isinstance(chunk, dict):
                raise LLMError("Ollama returned an unexpected response shape")
            if chunk.get("error"):
                raise LLMError(f"Ollama error: {str(chunk['error'])[:200]}")
            piece = chunk.get("response")
            if isinstance(piece, str):
                parts.append(piece)
            if chunk.get("done"):
                break
        text = "".join(parts)
        if not text.strip():
            raise LLMError("Ollama returned an empty response")
        return text