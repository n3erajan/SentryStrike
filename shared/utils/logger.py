import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from shared.config import get_infrastructure_settings


def configure_logging() -> None:
    settings = get_infrastructure_settings()
    log_file = (settings.log_file or "").strip()

    # Windows consoles default to cp1252, which cannot encode symbols like "≥"
    # used in verifier log messages. Force UTF-8 so logging never crashes on
    # Unicode; fall back to "replace" so a legacy terminal degrades gracefully
    # instead of raising UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(settings.log_level.upper())
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Browser-engine debug logs are valuable for diagnosing Playwright/crawl
    # issues without raising the global log level to DEBUG.
    logging.getLogger("app.core.crawler.browser_engine").setLevel(logging.DEBUG)

    # httpx logs bare URLs without scan context; sentry.http provides detail.
    for noisy_logger in ("httpx", "httpcore"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    # pymongo topology / connection debug chatter is high-volume and rarely
    # actionable during scans. Keep it at INFO even when the root logger is
    # set to DEBUG so it doesn't drown out scan-relevant log lines.
    for noisy_logger in (
        "pymongo",
        "pymongo.connection",
        "pymongo.topology",
        "pymongo.serverSelection",
    ):
        logging.getLogger(noisy_logger).setLevel(logging.INFO)
