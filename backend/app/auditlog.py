"""Journal d'audit infalsifiable (chaîne SHA-256) et stockage SQLite WAL."""
import hashlib
import json
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from . import config

_lock = threading.Lock()
_last: str | None = None
_ZERO = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_hash(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _log_path():
    return config.DATA_DIR / "audit.jsonl"


def _tail_hash() -> str:
    path, last = _log_path(), _ZERO
    if path.exists():
        for line in path.open(encoding="utf-8"):
            if line.strip():
                try:
                    last = json.loads(line).get("hash", last)
                except ValueError:
                    pass
    return last


def append_event(event: dict) -> None:
    global _last
    with _lock:
        if _last is None:
            _last = _tail_hash()
        rec = {"timestamp": utc_now(), "prev": _last, **event}
        rec["hash"] = canonical_hash(rec)
        _log_path().parent.mkdir(parents=True, exist_ok=True)
        with _log_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        _last = rec["hash"]


def verify_chain() -> dict:
    prev, n = _ZERO, 0
    path = _log_path()
    if path.exists():
        for line in path.open(encoding="utf-8"):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                return {"valid": False, "broken_at": n + 1, "records": n}
            h = rec.pop("hash", "")
            if rec.get("prev") != prev or canonical_hash(rec) != h:
                return {"valid": False, "broken_at": n + 1, "records": n}
            prev, n = h, n + 1
    return {"valid": True, "records": n}


def _db() -> sqlite3.Connection:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DATA_DIR / "agata.db", timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("CREATE TABLE IF NOT EXISTS audits(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL)")
    return c


def save_audit(audit: dict) -> None:
    with closing(_db()) as c, c:
        c.execute("INSERT OR REPLACE INTO audits VALUES (?,?,?)",
                  (audit["audit_id"], audit["created_at"], json.dumps(audit, ensure_ascii=False)))


def load_audit(audit_id: str) -> dict | None:
    with closing(_db()) as c:
        row = c.execute("SELECT payload FROM audits WHERE id=?", (audit_id,)).fetchone()
    return json.loads(row[0]) if row else None


def list_audits(limit: int = 25) -> list[dict]:
    with closing(_db()) as c:
        rows = c.execute("SELECT payload FROM audits ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [json.loads(r[0]) for r in rows]
