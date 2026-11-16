"""Tests for secret / personal-data detection and redaction."""

import unittest

from ai_threat_model.sensitive import (
    find_token,
    is_pii_name,
    is_placeholder,
    is_secret_name,
    looks_like_secret_value,
    mask,
    redact,
)
from tests.helpers import fake_github_token, fake_openai_key


class SecretNameTests(unittest.TestCase):
    def test_recognizes_credential_identifiers(self) -> None:
        for name in ("OPENAI_API_KEY", "apiKey", "db-password", "client_secret", "settings.auth_token"):
            with self.subTest(name=name):
                self.assertTrue(is_secret_name(name))

    def test_ignores_token_counters(self) -> None:
        for name in ("max_tokens", "token_count", "num_tokens", "token_limit", "tokenizer"):
            with self.subTest(name=name):
                self.assertFalse(is_secret_name(name))

    def test_recognizes_personal_data_identifiers(self) -> None:
        for name in ("customerEmail", "ssn", "phone_number", "date_of_birth", "patient_id"):
            with self.subTest(name=name):
                self.assertTrue(is_pii_name(name))
        self.assertFalse(is_pii_name("message"))


class ValueTests(unittest.TestCase):
    def test_placeholders_are_not_secrets(self) -> None:
        for value in ("<your-key>", "changeme", "${OPENAI_API_KEY}", "xxxxxxxxxx", "your-api-key-here"):
            with self.subTest(value=value):
                self.assertTrue(is_placeholder(value))
                self.assertFalse(looks_like_secret_value(value))

    def test_realistic_value_looks_like_secret(self) -> None:
        self.assertTrue(looks_like_secret_value("acme-db-pass-2024"))
        self.assertFalse(looks_like_secret_value("short"))

    def test_find_token_detects_known_formats(self) -> None:
        self.assertEqual(find_token(f"key={fake_openai_key()}"), fake_openai_key())
        self.assertEqual(find_token(fake_github_token()), fake_github_token())
        self.assertIsNone(find_token("nothing secret here"))


class RedactionTests(unittest.TestCase):
    def test_mask_keeps_only_prefix(self) -> None:
        self.assertEqual(mask("abcdefgh"), "abcd…[REDACTED]")
        self.assertEqual(mask("abc"), "[REDACTED]")

    def test_redact_masks_tokens_and_secret_assignments(self) -> None:
        text = f'client = OpenAI(api_key="{fake_openai_key()}"); password = "hunter2hunter2"'
        redacted = redact(text)
        self.assertNotIn(fake_openai_key(), redacted)
        self.assertNotIn("hunter2hunter2", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_redact_leaves_ordinary_text_alone(self) -> None:
        text = "model = ChatOllama(model='qwen2.5-coder:7b', temperature=0)"
        self.assertEqual(redact(text), text)


if __name__ == "__main__":
    unittest.main()
