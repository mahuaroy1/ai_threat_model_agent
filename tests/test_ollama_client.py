"""Ollama client: URL policy, request shape, retries, limits, and error handling.

All network traffic goes to an in-process stub server on 127.0.0.1.
"""

import os
import unittest
from unittest import mock

from ai_threat_model import ollama_client
from ai_threat_model.errors import LLMError
from ai_threat_model.ollama_client import OllamaClient, validate_base_url
from tests.helpers import StubOllama, unused_local_port

OK = (200, {"response": "All good", "done": True})


def client_for(stub: StubOllama, **overrides) -> OllamaClient:
    options = {"base_url": stub.url, "model": "qwen2.5-coder:7b", "timeout_seconds": 5, "max_retries": 2}
    options.update(overrides)
    return OllamaClient(**options)


class UrlValidationTests(unittest.TestCase):
    def test_loopback_urls_are_accepted(self) -> None:
        for url in ("http://127.0.0.1:11434", "http://localhost:11434/", "http://[::1]:11434"):
            with self.subTest(url=url):
                self.assertTrue(validate_base_url(url).startswith("http"))
        self.assertEqual(validate_base_url("http://127.0.0.1:11434/api/x"), "http://127.0.0.1:11434")

    def test_remote_urls_require_opt_in(self) -> None:
        with self.assertRaises(LLMError):
            validate_base_url("http://ollama.example.com:11434")
        self.assertEqual(
            validate_base_url("https://ollama.example.com", allow_remote=True), "https://ollama.example.com"
        )

    def test_bad_schemes_and_credentials_are_rejected(self) -> None:
        for url in ("file:///etc/passwd", "ftp://127.0.0.1", "127.0.0.1:11434", "http://user:pw@127.0.0.1:11434"):
            with self.subTest(url=url), self.assertRaises(LLMError):
                validate_base_url(url)

    def test_invalid_configuration_is_rejected(self) -> None:
        for overrides in ({"model": ""}, {"model": "qwen 2.5"}, {"timeout_seconds": 0}, {"max_retries": 6},
                          {"max_retries": -1}):
            with self.subTest(overrides=overrides), self.assertRaises(LLMError):
                OllamaClient(**overrides)

    def test_defaults_match_documented_limits(self) -> None:
        client = OllamaClient()
        self.assertEqual(client.max_retries, 2)
        self.assertEqual(client.timeout_seconds, 300)
        self.assertEqual(client.model, "qwen2.5-coder:7b")


@mock.patch.object(ollama_client, "RETRY_BACKOFF_SECONDS", 0)
class GenerateTests(unittest.TestCase):
    def test_success_sends_expected_request(self) -> None:
        with StubOllama([OK]) as stub:
            text = client_for(stub).generate("Summarize", system="Be brief")
        self.assertEqual(text, "All good")
        [request] = stub.requests
        self.assertEqual(request["path"], "/api/generate")
        body = request["body"]
        self.assertEqual(body["model"], "qwen2.5-coder:7b")
        self.assertEqual((body["prompt"], body["system"], body["stream"]), ("Summarize", "Be brief", True))
        self.assertEqual(body["options"]["num_predict"], 1024)
        self.assertEqual(body["options"]["num_ctx"], 8192)

    def test_streamed_chunks_are_concatenated(self) -> None:
        stream = (b'{"response":"Top ","done":false}\n{"response":"risk","done":false}\n\n'
                  b'{"response":"","done":true}\n{"response":"ignored after done"}\n')
        with StubOllama([(200, stream)]) as stub:
            self.assertEqual(client_for(stub).generate("x"), "Top risk")

    def test_error_in_the_middle_of_a_stream(self) -> None:
        stream = b'{"response":"partial"}\n{"error":"model crashed"}\n'
        with StubOllama([(200, stream)]) as stub, self.assertRaisesRegex(LLMError, "model crashed"):
            client_for(stub).generate("x")

    def test_transient_errors_are_retried(self) -> None:
        with StubOllama([(503, {}), (503, {}), OK]) as stub:
            self.assertEqual(client_for(stub).generate("x"), "All good")
        self.assertEqual(len(stub.requests), 3)

    def test_gives_up_after_max_retries(self) -> None:
        with StubOllama([(503, {})]) as stub:
            with self.assertRaisesRegex(LLMError, "gave up after 3 attempt"):
                client_for(stub).generate("x")
        self.assertEqual(len(stub.requests), 3)

    def test_zero_retries_means_single_attempt(self) -> None:
        with StubOllama([(500, {})]) as stub:
            with self.assertRaisesRegex(LLMError, "gave up after 1 attempt"):
                client_for(stub, max_retries=0).generate("x")
        self.assertEqual(len(stub.requests), 1)

    def test_missing_model_is_not_retried_and_hints_pull(self) -> None:
        with StubOllama([(404, {"error": "model not found"})]) as stub:
            with self.assertRaisesRegex(LLMError, "ollama pull qwen2.5-coder:7b"):
                client_for(stub).generate("x")
        self.assertEqual(len(stub.requests), 1)

    def test_malformed_and_error_responses(self) -> None:
        cases = [
            ((200, b"not json"), "malformed"),
            ((200, ["a", "list"]), "unexpected response shape"),
            ((200, {"error": "out of memory"}), "out of memory"),
            ((200, {"response": "   "}), "empty response"),
        ]
        for response, message in cases:
            with self.subTest(message=message), StubOllama([response]) as stub:
                with self.assertRaisesRegex(LLMError, message):
                    client_for(stub).generate("x")
                self.assertEqual(len(stub.requests), 1)

    def test_oversized_response_is_rejected(self) -> None:
        with mock.patch.object(ollama_client, "MAX_RESPONSE_BYTES", 50):
            with StubOllama([(200, {"response": "x" * 500})]) as stub:
                with self.assertRaisesRegex(LLMError, "size limit"):
                    client_for(stub).generate("x")

    def test_slow_server_times_out_and_retries(self) -> None:
        with StubOllama([OK], delay=1.5) as stub:
            with self.assertRaisesRegex(LLMError, "gave up after 2 attempt"):
                client_for(stub, timeout_seconds=0.3, max_retries=1).generate("x")

    def test_connection_refused(self) -> None:
        client = OllamaClient(base_url=f"http://127.0.0.1:{unused_local_port()}", timeout_seconds=2, max_retries=1)
        with self.assertRaisesRegex(LLMError, "gave up after 2 attempt"):
            client.generate("x")

    def test_proxy_environment_is_ignored(self) -> None:
        proxy = f"http://127.0.0.1:{unused_local_port()}"
        environment = {"HTTP_PROXY": proxy, "http_proxy": proxy, "NO_PROXY": "", "no_proxy": ""}
        with mock.patch.dict(os.environ, environment), StubOllama([OK]) as stub:
            self.assertEqual(client_for(stub).generate("x"), "All good")
        self.assertEqual(len(stub.requests), 1)


if __name__ == "__main__":
    unittest.main()
