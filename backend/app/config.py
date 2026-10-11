"""Configuration centralisée (variables d'environnement, valeurs par défaut fail-closed)."""
import os
from pathlib import Path


def _csv(name: str, default: str = "") -> list[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


VERSION = "2.0.0"
MODE = os.getenv("AGATA_MODE", "lab").lower()
ACTIVE_CHECKS = os.getenv("AGATA_ACTIVE_CHECKS", "false").lower() == "true"
ALLOWED_TARGETS = [t.lower() for t in _csv("AGATA_ALLOWED_TARGETS", "127.0.0.1,localhost")]
ALLOWED_PORTS = {int(p) for p in _csv("AGATA_ALLOWED_PORTS", "8000,8080,8443") if p.isascii() and p.isdigit() and 0 < int(p) < 65536}
DATA_DIR = Path(os.getenv("AGATA_DATA_DIR", "./data")).resolve()
API_TOKEN = os.getenv("AGATA_API_TOKEN", "")
PROXY_HOPS = _int("AGATA_PROXY_HOPS", 0)
RATE_PER_MIN = _int("AGATA_RATE_PER_MIN", 120)
HEAVY_PER_MIN = _int("AGATA_HEAVY_PER_MIN", 10)
CORS_ORIGINS = _csv("AGATA_CORS_ORIGINS")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ADMIN_CHAT_ID = os.getenv("TELEGRAM_ADMIN_CHAT_ID", "")
PLAN = os.getenv("AGATA_PLAN", "community")
DAILY_QUOTA = _int("AGATA_DAILY_QUOTA", 200)
