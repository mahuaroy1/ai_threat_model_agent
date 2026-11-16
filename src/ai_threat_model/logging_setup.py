"""Logging configuration with secret redaction.

Every record is formatted and then passed through :func:`sensitive.redact`, so
credentials are masked whether they appear in the message, its arguments, or
an exception traceback. Logs go to stderr and, optionally, to a size-rotated
file so long-running CI usage cannot fill the disk.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .errors import ThreatModelError
from .sensitive import redact

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
CONSOLE_FORMAT = "%(levelname)s: %(message)s"
MAX_LOG_BYTES = 5_000_000
LOG_BACKUP_COUNT = 3
PACKAGE_LOGGER = "ai_threat_model"


class RedactingFormatter(logging.Formatter):
    """Formatter that masks secrets in the fully rendered log line."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def configure_logging(level: str = "WARNING", log_file: Path | None = None) -> logging.Logger:
    """Configure the package logger and return it. Safe to call more than once.

    Raises:
        ThreatModelError: If the level is unknown or the log file cannot be opened.
    """
    numeric_level = logging.getLevelName(level.upper())
    if not isinstance(numeric_level, int):
        raise ThreatModelError(f"Unknown log level: {level}")

    logger = logging.getLogger(PACKAGE_LOGGER)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(min(numeric_level, logging.INFO) if log_file else numeric_level)
    logger.propagate = False

    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    console.setFormatter(RedactingFormatter(CONSOLE_FORMAT))
    logger.addHandler(console)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file, maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8",
            )
        except OSError as error:
            raise ThreatModelError(f"Cannot open log file {log_file}: {error.strerror or error}") from error
        # The file always captures INFO and above for troubleshooting, even when the console is quieter.
        file_handler.setLevel(min(numeric_level, logging.INFO))
        file_handler.setFormatter(RedactingFormatter(LOG_FORMAT))
        logger.addHandler(file_handler)
    return logger
