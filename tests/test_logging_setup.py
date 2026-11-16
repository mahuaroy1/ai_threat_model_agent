"""Logging configuration: redaction, file output, and idempotency."""

import logging
import unittest

from ai_threat_model.errors import ThreatModelError
from ai_threat_model.logging_setup import PACKAGE_LOGGER, configure_logging
from tests.helpers import TempDirTestCase, fake_github_token


def reset_package_logger() -> None:
    """Close handlers so temp files can be deleted on Windows, and restore defaults."""
    logger = logging.getLogger(PACKAGE_LOGGER)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(logging.NOTSET)
    logger.propagate = True


class LoggingSetupTests(TempDirTestCase):
    def tearDown(self) -> None:
        reset_package_logger()
        super().tearDown()

    def test_log_file_masks_secrets(self) -> None:
        log_file = self.tmp / "logs" / "scan.log"
        configure_logging("ERROR", log_file)
        logging.getLogger(f"{PACKAGE_LOGGER}.test").info("token=%s", fake_github_token())
        reset_package_logger()  # flush and close before reading
        content = log_file.read_text(encoding="utf-8")
        self.assertIn("[REDACTED]", content)
        self.assertNotIn(fake_github_token(), content)

    def test_configuring_twice_does_not_duplicate_handlers(self) -> None:
        configure_logging("INFO")
        logger = configure_logging("WARNING")
        self.assertEqual(len(logger.handlers), 1)
        self.assertEqual(logger.level, logging.WARNING)
        self.assertFalse(logger.propagate)

    def test_invalid_level_raises(self) -> None:
        with self.assertRaises(ThreatModelError):
            configure_logging("LOUD")

    def test_unopenable_log_file_raises(self) -> None:
        blocker = self.tmp / "file"
        blocker.write_text("x", encoding="utf-8")
        with self.assertRaises(ThreatModelError):
            configure_logging("INFO", blocker / "scan.log")


if __name__ == "__main__":
    unittest.main()
