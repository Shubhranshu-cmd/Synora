from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

log = logging.getLogger("synora.persistence")

BACKUP_DIR          = Path(os.environ.get("SYNORA_BACKUP_DIR", "")) or None
BACKUP_KEEP_DAYS    = int(os.environ.get("SYNORA_BACKUP_KEEP_DAYS", "30"))
BACKUP_INTERVAL_H   = int(os.environ.get("SYNORA_BACKUP_INTERVAL_H", "6"))
INTEGRITY_INTERVAL_H= int(os.environ.get("SYNORA_INTEGRITY_INTERVAL_H", "12"))

MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (1, "initial schema", [
        """CREATE TABLE IF NOT EXISTS schema_versions (
            version     INTEGER PRIMARY KEY,
            description TEXT,
            applied_at  TEXT DEFAULT (datetime('now'))
        )""",
    ]),
    (2, "add message reactions column", [
        "ALTER TABLE messages ADD COLUMN reactions TEXT DEFAULT '{}'",
    ]),
    (3, "add call quality column", [
        "ALTER TABLE call_logs ADD COLUMN quality TEXT",
    ]),
    (4, "add user device_tokens for push notifications", [
        """CREATE TABLE IF NOT EXISTS device_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            owner       TEXT NOT NULL,
            token       TEXT NOT NULL,
            platform    TEXT DEFAULT 'web',
            created_at  TEXT DEFAULT (datetime('now')),
            UNIQUE(owner, token)
        )""",
    ]),
    (5, "add deleted_messages soft-delete", [
        "ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN deleted_at TEXT",
    ]),
    (6, "add backup_log table", [
        """CREATE TABLE IF NOT EXISTS backup_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            path        TEXT NOT NULL,
            size_bytes  INTEGER,
            checksum    TEXT,
            ts          TEXT DEFAULT (datetime('now')),
            status      TEXT DEFAULT 'ok'
        )""",
    ]),
    (7, "add integrity_log table", [
        """CREATE TABLE IF NOT EXISTS integrity_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT DEFAULT (datetime('now')),
            result      TEXT,
            details     TEXT
        )""",
    ]),
    (8, "add rate_limit table", [
        """CREATE TABLE IF NOT EXISTS rate_limit (
            key         TEXT PRIMARY KEY,
            count       INTEGER DEFAULT 1,
            window_start TEXT DEFAULT (datetime('now'))
        )""",
    ]),
    (9, "add user_audit table", [
        """CREATE TABLE IF NOT EXISTS user_audit (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            number      TEXT NOT NULL,
            event       TEXT NOT NULL,
            ip          TEXT,
            details     TEXT,
            ts          TEXT DEFAULT (datetime('now'))
        )""",
        "CREATE INDEX IF NOT EXISTS idx_audit_number ON user_audit(number)",
        "CREATE INDEX IF NOT EXISTS idx_audit_ts ON user_audit(ts)",
    ]),
    (10, "add blocked_ips table for persistent bans", [
        """CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            reason      TEXT,
            blocked_at  TEXT DEFAULT (datetime('now')),
            expires_at  TEXT
        )""",
    ]),
    (11, "add key_backup column to users", [
        "ALTER TABLE users ADD COLUMN key_backup TEXT",
    ]),
    (12, "add abuse_reports table", [
        """CREATE TABLE IF NOT EXISTS abuse_reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter    TEXT NOT NULL,
            reported    TEXT NOT NULL,
            reason      TEXT NOT NULL,
            details     TEXT,
            msg_id      TEXT,
            status      TEXT DEFAULT 'pending',
            ts          TEXT DEFAULT (datetime('now'))
        )""",
        "CREATE INDEX IF NOT EXISTS idx_reports_reported ON abuse_reports(reported)",
        "CREATE INDEX IF NOT EXISTS idx_reports_ts ON abuse_reports(ts)",
    ]),
    (13, "add otp_log table", [
        """CREATE TABLE IF NOT EXISTS otp_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT NOT NULL,
            status      TEXT DEFAULT 'sent',
            ip          TEXT,
            ts          TEXT DEFAULT (datetime('now'))
        )""",
    ]),
]

def run_migrations(db_path: str) -> int:
    """
    Apply any pending migrations safely.
    Returns the number of new migrations applied.
    Never drops or truncates existing data.
    """
    conn = sqlite3.connect(db_path, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    applied = 0
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_versions (
                version     INTEGER PRIMARY KEY,
                description TEXT,
                applied_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()

        done = {r["version"] for r in conn.execute("SELECT version FROM schema_versions")}

        for (ver, desc, sqls) in MIGRATIONS:
            if ver in done:
                continue
            log.info(f"[migration] Applying v{ver}: {desc}")
            try:
                for sql in sqls:
                    try:
                        conn.execute(sql)
                    except sqlite3.OperationalError as e:
                        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                            log.debug(f"[migration] Skipped (already exists): {e}")
                        else:
                            raise
                conn.execute(
                    "INSERT OR IGNORE INTO schema_versions (version, description) VALUES (?,?)",
                    (ver, desc)
                )
                conn.commit()
                applied += 1
                log.info(f"[migration] v{ver} applied OK")
            except Exception as e:
                conn.rollback()
                log.error(f"[migration] v{ver} FAILED: {e}")
    finally:
        conn.close()
    if applied:
        log.info(f"[migration] {applied} migration(s) applied")
    return applied


def checkpoint_wal(db_path: str):
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception as e:
        log.warning(f"[wal] checkpoint failed: {e}")


def run_integrity_check(db_path: str) -> tuple[bool, str]:
    try:
        conn = sqlite3.connect(db_path, timeout=20)
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        conn.close()
        result_str = ", ".join(r[0] for r in rows)
        ok = (result_str == "ok")
        try:
            conn2 = sqlite3.connect(db_path, timeout=10)
            conn2.execute(
                "INSERT OR IGNORE INTO integrity_log (result, details) VALUES (?,?)",
                ("ok" if ok else "FAILED", result_str)
            )
            conn2.commit()
            conn2.close()
        except Exception:
            pass
        if ok:
            log.info("[integrity] Database OK")
        else:
            log.error(f"[integrity] PROBLEMS DETECTED: {result_str}")
        return ok, result_str
    except Exception as e:
        log.error(f"[integrity] check error: {e}")
        return False, str(e)

def _resolve_backup_dir(db_path: str) -> Path:
    global BACKUP_DIR
    if BACKUP_DIR and Path(BACKUP_DIR).is_dir():
        return Path(BACKUP_DIR)
    candidate = Path(db_path).parent / "synora_backups"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except Exception:
        fallback = Path("/tmp/synora_backups")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def create_backup(db_path: str, label: str = "auto") -> Optional[Path]:
    db = Path(db_path)
    if not db.exists():
        log.warning("[backup] Source DB not found — skipping")
        return None

    bdir = _resolve_backup_dir(db_path)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"synora_{label}_{ts}.db.gz"
    dest = bdir / name
    tmp  = bdir / f"_tmp_{ts}.db"

    try:
        checkpoint_wal(db_path)

        src_conn = sqlite3.connect(db_path, timeout=30)
        dst_conn = sqlite3.connect(str(tmp))
        src_conn.backup(dst_conn, pages=512)
        src_conn.close()
        dst_conn.close()

        with open(tmp, "rb") as fin, gzip.open(str(dest), "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout)
        tmp.unlink(missing_ok=True)

        checksum = _file_sha256(dest)
        size     = dest.stat().st_size

        try:
            conn = sqlite3.connect(db_path, timeout=10)
            conn.execute(
                "INSERT INTO backup_log (path, size_bytes, checksum, status) VALUES (?,?,?,?)",
                (str(dest), size, checksum, "ok")
            )
            conn.commit()
            conn.close()
        except Exception as le:
            log.debug(f"[backup] Could not log to backup_log: {le}")

        log.info(f"[backup] Created: {dest.name} ({size//1024} KB) sha256={checksum[:12]}…")
        _prune_backups(bdir, db_path)
        return dest

    except Exception as e:
        log.error(f"[backup] FAILED: {e}")
        tmp.unlink(missing_ok=True)
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            conn.execute(
                "INSERT INTO backup_log (path, size_bytes, checksum, status) VALUES (?,?,?,?)",
                (str(dest), 0, "", f"FAILED: {e}")
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
        return None

def _prune_backups(bdir: Path, db_path: str):
    cutoff = time.time() - (BACKUP_KEEP_DAYS * 86400)
    removed = 0
    for f in bdir.glob("synora_*.db.gz"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except Exception:
            pass
    if removed:
        log.info(f"[backup] Pruned {removed} old backup(s) (>{BACKUP_KEEP_DAYS}d old)")

def restore_from_backup(backup_path: str, db_path: str) -> bool:
    src  = Path(backup_path)
    dest = Path(db_path)
    if not src.exists():
        log.error(f"[restore] Backup not found: {src}")
        return False

    safety = dest.with_suffix(".pre_restore.db")
    if dest.exists():
        try:
            shutil.copy2(str(dest), str(safety))
            log.info(f"[restore] Current DB preserved at {safety}")
        except Exception as e:
            log.warning(f"[restore] Could not preserve current DB: {e}")

    try:
        with gzip.open(str(src), "rb") as fin, open(str(dest), "wb") as fout:
            shutil.copyfileobj(fin, fout)
        log.info(f"[restore] Successfully restored from {src.name}")
        return True
    except Exception as e:
        log.error(f"[restore] FAILED: {e}")
        if safety.exists():
            shutil.copy2(str(safety), str(dest))
            log.info("[restore] Rolled back to pre-restore DB")
        return False

def list_backups(db_path: str) -> list[dict]:
    bdir = _resolve_backup_dir(db_path)
    backups = []
    for f in sorted(bdir.glob("synora_*.db.gz"), reverse=True):
        stat = f.stat()
        backups.append({
            "filename":   f.name,
            "path":       str(f),
            "size_bytes": stat.st_size,
            "size_kb":    round(stat.st_size / 1024, 1),
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return backups

_rl_lock = threading.Lock()
_rl_cache: dict[str, tuple[int, float]] = {}

def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
    now = time.monotonic()
    with _rl_lock:
        count, start = _rl_cache.get(key, (0, now))
        if now - start > window_seconds:
            count = 1
            start = now
        else:
            count += 1
        _rl_cache[key] = (count, start)
        allowed = count <= max_requests
        remaining = max(0, max_requests - count)
    return allowed, remaining

_BLOCKED_IPS: set[str] = set()
_block_lock = threading.Lock()
_db_path_for_blocks: str = ""

def load_blocked_ips(db_path: str):
    """
    Load persisted blocked IPs from DB into memory at startup.
    Call this once after migrations have run.
    """
    global _db_path_for_blocks
    _db_path_for_blocks = db_path
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        rows = conn.execute(
            "SELECT ip FROM blocked_ips WHERE expires_at IS NULL OR expires_at > datetime('now')"
        ).fetchall()
        conn.close()
        with _block_lock:
            for r in rows:
                _BLOCKED_IPS.add(r[0])
        log.info(f"[security] Loaded {len(rows)} persisted IP block(s)")
    except Exception as e:
        log.warning(f"[security] Could not load blocked IPs: {e}")

def block_ip(ip: str, reason: str = "rate_limit", expires_hours: Optional[int] = None):
    """Block an IP in memory and persist to DB."""
    with _block_lock:
        _BLOCKED_IPS.add(ip)
    log.warning(f"[security] Blocked IP: {ip} ({reason})")
    if _db_path_for_blocks:
        try:
            expires = None
            if expires_hours:
                from datetime import timedelta
                expires = (datetime.now(timezone.utc) + timedelta(hours=expires_hours)).isoformat()
            conn = sqlite3.connect(_db_path_for_blocks, timeout=5)
            conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, reason, expires_at) VALUES (?,?,?)",
                (ip, reason, expires)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"[security] Could not persist IP block: {e}")

def is_blocked(ip: str) -> bool:
    with _block_lock:
        return ip in _BLOCKED_IPS

def unblock_ip(ip: str):
    """Remove an IP from the block list."""
    with _block_lock:
        _BLOCKED_IPS.discard(ip)
    if _db_path_for_blocks:
        try:
            conn = sqlite3.connect(_db_path_for_blocks, timeout=5)
            conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
            conn.commit()
            conn.close()
        except Exception:
            pass

def audit_event(db_path: str, number: str, event: str, ip: str = "", details: str = ""):
    """Write a security audit event. Fire-and-forget — never raises."""
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.execute(
            "INSERT INTO user_audit (number, event, ip, details) VALUES (?,?,?,?)",
            (number, event, ip, details)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def sanitize_input(s: str, max_len: int = 500) -> str:
    """Strip null bytes and limit length. For any user-supplied string."""
    if not isinstance(s, str):
        return ""
    return s.replace("\x00", "").strip()[:max_len]

class DataGuardian:
    """
    Background thread that:
      • Runs WAL checkpoint every 30 min
      • Creates automatic backup every BACKUP_INTERVAL_H hours
      • Runs integrity check every INTEGRITY_INTERVAL_H hours
      • Cleans expired IP blocks every hour
    """
    def __init__(self, db_path: str):
        self.db_path     = db_path
        self._stop       = threading.Event()
        self._thread     = threading.Thread(target=self._run, daemon=True, name="DataGuardian")
        self._last_backup    = 0.0
        self._last_integrity = 0.0
        self._last_unblock   = 0.0

    def start(self):
        load_blocked_ips(self.db_path)
        self._thread.start()
        log.info("[guardian] DataGuardian started")

    def stop(self):
        self._stop.set()

    def _run(self):
        time.sleep(5)
        self._do_integrity()
        self._do_backup("startup")

        while not self._stop.is_set():
            now = time.time()

            checkpoint_wal(self.db_path)

            if now - self._last_backup >= BACKUP_INTERVAL_H * 3600:
                self._do_backup("auto")

            if now - self._last_integrity >= INTEGRITY_INTERVAL_H * 3600:
                self._do_integrity()

            if now - self._last_unblock >= 3600:
                self._clean_expired_blocks()
                self._last_unblock = now

            self._stop.wait(timeout=1800)

    def _do_backup(self, label: str):
        result = create_backup(self.db_path, label=label)
        self._last_backup = time.time()
        if result:
            log.info(f"[guardian] Backup OK → {result.name}")
        else:
            log.error("[guardian] Backup FAILED")

    def _do_integrity(self):
        ok, details = run_integrity_check(self.db_path)
        self._last_integrity = time.time()
        if not ok:
            log.error(f"[guardian] ⚠️  DB INTEGRITY ISSUE: {details}")
            create_backup(self.db_path, label="emergency")

    def _clean_expired_blocks(self):
        """Remove expired IP bans from DB and in-memory set."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            rows = conn.execute(
                "SELECT ip FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
            ).fetchall()
            if rows:
                conn.execute(
                    "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
                )
                conn.commit()
                with _block_lock:
                    for r in rows:
                        _BLOCKED_IPS.discard(r[0])
                log.info(f"[guardian] Expired {len(rows)} IP block(s)")
            conn.close()
        except Exception as e:
            log.debug(f"[guardian] block cleanup error: {e}")

def export_user_data(db_path: str, number: str, decrypt_fn: Optional[Callable[[str], str]] = None) -> dict:
    """
    Export all data belonging to a user as a JSON-serialisable dict.
    decrypt_fn: callable that decrypts server-side encrypted content.
                If None, content is exported as-is (encrypted).
    """
    try:
        conn = sqlite3.connect(db_path, timeout=15)
        conn.row_factory = sqlite3.Row

        user = dict(conn.execute(
            "SELECT number,name,color,status,online,last_seen,created_at FROM users WHERE number=?",
            (number,)
        ).fetchone() or {})

        contacts = [dict(r) for r in conn.execute(
            "SELECT number,saved_name FROM contacts WHERE owner=?", (number,)
        ).fetchall()]

        messages_raw = conn.execute(
            """SELECT msg_id,sender,receiver,content,msg_type,status,ts
               FROM messages WHERE (sender=? OR receiver=?) AND deleted=0
               ORDER BY ts""",
            (number, number)
        ).fetchall()

        messages = []
        for r in messages_raw:
            row = dict(r)
            if decrypt_fn:
                try:
                    row["content"] = decrypt_fn(row["content"])
                except Exception:
                    pass
            messages.append(row)

        call_history = [dict(r) for r in conn.execute(
            """SELECT call_id,caller,callee,call_type,status,duration,ts
               FROM call_logs WHERE caller=? OR callee=?
               ORDER BY ts""",
            (number, number)
        ).fetchall()]

        audit = [dict(r) for r in conn.execute(
            "SELECT event,ip,details,ts FROM user_audit WHERE number=? ORDER BY ts DESC LIMIT 200",
            (number,)
        ).fetchall()]

        conn.close()

        return {
            "export_version": "2.1",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "contacts": contacts,
            "messages": messages,
            "call_history": call_history,
            "audit_log": audit,
            "note": (
                "Messages in this export have the server-side encryption layer removed. "
                "Content that was end-to-end encrypted by the sender will appear as "
                "the client-E2E payload — decrypt it with your Synora private key."
            )
        }
    except Exception as e:
        log.error(f"[export] Failed for {number}: {e}")
        return {"error": str(e)}