"""Allowlisted JSON events: never serialize prompts, credentials or exceptions."""

from datetime import datetime, timezone
import json
import logging

from .config import Settings

FIELDS = ("actor", "event", "reason", "target", "scope_decision", "action", "result", "correlation_id")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        result = {"timestamp": datetime.now(timezone.utc).isoformat(), "level": record.levelname}
        for key in FIELDS:
            if hasattr(record, key):
                result[key] = getattr(record, key)
        return json.dumps(result, ensure_ascii=True)


def configure_logging(settings: Settings) -> logging.Logger:
    settings.log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("abh")
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    logger.setLevel(settings.log_level)
    logger.propagate = False
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler(settings.log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger


def record_event(logger: logging.Logger, command: str, result: str, correlation_id: str) -> None:
    logger.info("", extra={"actor": "local_cli", "event": "command_completed",
                "reason": "user_requested_foundation_operation", "target": "local_workspace",
                "scope_decision": "not_applicable_no_target_execution", "action": command,
                "result": result, "correlation_id": correlation_id})
