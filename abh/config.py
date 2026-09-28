"""Explicit local configuration; process environment overrides .env."""

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
import os


class ConfigError(ValueError):
    pass


def read_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key.strip().isidentifier():
            raise ConfigError(f"Invalid .env syntax at line {number}")
        value = value.strip()
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ConfigError(f"Unclosed .env quote at line {number}")
            value = value[1:-1]
        values[key.strip()] = value
    return values


def boolean(values: Mapping[str, str], key: str, default: bool) -> bool:
    value = values.get(key, str(default)).strip().lower()
    if value not in {"true", "false"}:
        raise ConfigError(f"{key} must be true or false")
    return value == "true"


@dataclass(frozen=True)
class Settings:
    root: Path
    environment: str
    dry_run: bool
    require_human_approval: bool
    database_url: str
    log_level: str
    log_file: Path

    @classmethod
    def load(cls, root: Path, environ: Mapping[str, str] | None = None) -> "Settings":
        root = root.resolve()
        values = read_env(root / ".env")
        values.update(os.environ if environ is None else environ)
        level = values.get("LOG_LEVEL", "INFO").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError("Invalid LOG_LEVEL")
        environment = values.get("ABH_ENV", "development")
        if environment not in {"development", "test"}:
            raise ConfigError("Only development and test environments are supported")
        dry_run = boolean(values, "DRY_RUN", True)
        approval = boolean(values, "REQUIRE_HUMAN_APPROVAL", True)
        if not dry_run or not approval:
            raise ConfigError("Development requires DRY_RUN=true and REQUIRE_HUMAN_APPROVAL=true")
        log_path = Path(values.get("LOG_FILE", "data/abh.jsonl"))
        return cls(root, environment, dry_run, approval,
                   values.get("DATABASE_URL", "sqlite:///data/abh.db"), level,
                   log_path if log_path.is_absolute() else root / log_path)
