import os, sys, json, uuid, random, asyncio, hmac, base64, hashlib
import sqlite3, logging, socket, warnings, threading
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from pathlib import Path

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
warnings.filterwarnings("ignore", category=UserWarning)

try:
    import requests as _req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from sentence_transformers import SentenceTransformer
    HAS_EMBED = True
except ImportError:
    HAS_EMBED = False

try:
    from pywebpush import webpush, WebPushException
    HAS_WEBPUSH = True
except ImportError:
    HAS_WEBPUSH = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("synora")

from persistence import (
    run_migrations, run_integrity_check, create_backup,
    list_backups, restore_from_backup, export_user_data,
    DataGuardian, check_rate_limit, is_blocked, block_ip,
    audit_event, sanitize_input,
)

_guardian: Optional["DataGuardian"] = None

def _secret_key() -> str:
    env = os.environ.get("SECRET_KEY")
    if env and len(env) >= 32:
        return env
    kf = Path(__file__).parent / ".synora_secret"
    if kf.exists():
        try:
            k = kf.read_text().strip()
            if len(k) >= 32:
                return k
        except Exception:
            pass
    k = "synora-" + os.urandom(32).hex()
    try:
        kf.write_text(k)
        kf.chmod(0o600)
    except Exception:
        pass
    return k

def _msg_enc_key() -> bytes:
    """
    AES-256 key for encrypting message content at rest in SQLite.
    Priority:
      1. MSG_ENC_KEY env var — accepts any string:
         - 64-char hex → used directly as raw 32-byte key
         - anything else → SHA-256 hashed to a stable 32-byte key
           (safe for Render's auto-generated random values)
      2. .synora_msg_key file (persisted on disk)
      3. Random key generated once and saved to .synora_msg_key
    """
    env = os.environ.get("MSG_ENC_KEY", "")
    if env:
        if len(env) == 64:
            try:
                return bytes.fromhex(env)
            except ValueError:
                pass
        return hashlib.sha256(env.encode()).digest()
    kf = Path(__file__).parent / ".synora_msg_key"
    if kf.exists():
        try:
            raw = kf.read_text().strip()
            if len(raw) == 64:
                return bytes.fromhex(raw)
        except Exception:
            pass
    key = os.urandom(32)
    try:
        kf.write_text(key.hex())
        kf.chmod(0o600)
    except Exception:
        pass
    return key

SECRET_KEY    = _secret_key()
MSG_ENC_KEY   = _msg_enc_key()
ALGORITHM     = "HS256"
TOKEN_EXPIRE  = 60 * 24 * 7
PORT          = int(os.environ.get("PORT", 8080))
BASE_DIR      = Path(__file__).parent
STATIC_DIR    = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

VAPID_PRIVATE      = os.environ.get("VAPID_PRIVATE", "").strip()
VAPID_PUBLIC       = os.environ.get("VAPID_PUBLIC", "").strip()
VAPID_CLAIMS_EMAIL = os.environ.get("VAPID_CLAIMS_EMAIL", "mailto:admin@synora.app").strip()

_raw_origins = os.environ.get("SYNORA_ORIGINS", "")
if _raw_origins:
    ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = ["*"]

def _db_path() -> str:
    override = os.environ.get("SYNORA_DB")
    if override:
        return override
    try:
        import google.colab
        drive_root = "/content/drive"
        db_path = f"{drive_root}/MyDrive/synora.db"
        if not os.path.ismount(drive_root):
            from google.colab import drive as _d
            _d.mount(drive_root, force_remount=False)
        return db_path
    except ImportError:
        return str(BASE_DIR / "synora.db")

DB_PATH = _db_path()

try:
    import argon2 as _
    pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
except Exception:
    pwd_ctx = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

bearer = HTTPBearer(auto_error=False)

_aesgcm = AESGCM(MSG_ENC_KEY)

def encrypt_content(plaintext: str) -> str:
    """Encrypt message content → base64(nonce + ciphertext)."""
    nonce = os.urandom(12)
    ct = _aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_content(stored: str) -> str:
    """Decrypt stored content. Falls back to plaintext if not encrypted (migration)."""
    try:
        raw = base64.b64decode(stored)
        if len(raw) < 13:
            return stored
        nonce, ct = raw[:12], raw[12:]
        return _aesgcm.decrypt(nonce, ct, None).decode()
    except Exception:
        return stored

def is_encrypted(stored: str) -> bool:
    try:
        raw = base64.b64decode(stored)
        return len(raw) >= 29
    except Exception:
        return False

class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._local = threading.local()

    def conn(self):
        if not hasattr(self._local, "c") or self._local.c is None:
            c = sqlite3.connect(self.path, check_same_thread=False, timeout=15)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA cache_size=-8000")
            self._local.c = c
        return self._local.c

    def execute(self, sql, params=()):
        return self.conn().execute(sql, params)

    def commit(self):
        self.conn().commit()

    def rollback(self):
        try: self.conn().rollback()
        except Exception: pass

    def close(self):
        if hasattr(self._local, "c") and self._local.c:
            try: self._local.c.close()
            except Exception: pass
            self._local.c = None

    def fetchone(self, sql, params=()):
        return self.execute(sql, params).fetchone()

    def fetchall(self, sql, params=()):
        return self.execute(sql, params).fetchall()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()

_db = Database()

def db():
    return _db.conn()

def init_db():
    with Database() as d:
        d.execute("""
            CREATE TABLE IF NOT EXISTS users (
                number      TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                password    TEXT NOT NULL,
                public_key  TEXT,
                color       TEXT DEFAULT '#7C3AED',
                status      TEXT DEFAULT 'Hey there! I am using Synora.',
                online      INTEGER DEFAULT 0,
                last_seen   TEXT DEFAULT (datetime('now')),
                created_at  TEXT DEFAULT (datetime('now'))
            )""")
        d.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                owner       TEXT NOT NULL,
                number      TEXT NOT NULL,
                saved_name  TEXT NOT NULL,
                UNIQUE(owner, number)
            )""")
        d.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id      TEXT UNIQUE NOT NULL,
                sender      TEXT NOT NULL,
                receiver    TEXT NOT NULL,
                content     TEXT NOT NULL,
                msg_type    TEXT DEFAULT 'text',
                status      TEXT DEFAULT 'sent',
                ts          TEXT DEFAULT (datetime('now'))
            )""")
        d.execute("""
            CREATE TABLE IF NOT EXISTS call_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id     TEXT UNIQUE NOT NULL,
                caller      TEXT NOT NULL,
                callee      TEXT NOT NULL,
                call_type   TEXT NOT NULL,
                status      TEXT DEFAULT 'missed',
                duration    INTEGER DEFAULT 0,
                ts          TEXT DEFAULT (datetime('now'))
            )""")
        d.execute("""
            CREATE TABLE IF NOT EXISTS message_embeddings (
                msg_id      TEXT PRIMARY KEY,
                embedding   BLOB,
                FOREIGN KEY (msg_id) REFERENCES messages(msg_id) ON DELETE CASCADE
            )""")
        d.execute("CREATE INDEX IF NOT EXISTS idx_msg_sender ON messages(sender)")
        d.execute("CREATE INDEX IF NOT EXISTS idx_msg_receiver ON messages(receiver)")
        d.execute("CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(ts)")
        d.execute("CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner)")
        d.commit()
    print("✅ Database ready →", os.path.abspath(DB_PATH))

COLORS = ['#7C3AED','#2563EB','#059669','#DC2626','#D97706','#DB2777','#0891B2','#6366F1']

def _gen_number_sync() -> str:
    with Database() as d:
        for digits in range(7, 11):
            lo, hi = 10**(digits-1), 10**digits - 1
            _row = d.fetchone("SELECT COUNT(*) AS c FROM users WHERE length(number)=?", (digits,))
            used = _row["c"] if _row is not None else 0
            if used >= (hi - lo + 1):
                continue
            for _ in range(2000):
                n = str(random.randint(lo, hi))
                if not d.fetchone("SELECT 1 FROM users WHERE number=?", (n,)):
                    return n
    raise RuntimeError("Number space exhausted")

async def gen_number() -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _gen_number_sync)

def hash_pw(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_pw(pw: str, h: str) -> bool:
    try:
        return pwd_ctx.verify(pw, h)
    except Exception:
        return False

def make_token(number: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode({"sub": number, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[str]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except JWTError:
        return None

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    if not creds:
        raise HTTPException(401, "Authentication required")
    number = decode_token(creds.credentials)
    if not number:
        raise HTTPException(401, "Invalid or expired token — please sign in again")
    with Database() as d:
        if not d.fetchone("SELECT 1 FROM users WHERE number=?", (number,)):
            raise HTTPException(401, "Account not found")
    return number

embed_model = None

def _load_embed_sync():
    global embed_model
    if not HAS_EMBED:
        print("ℹ️  sentence-transformers not installed — keyword search enabled")
        return
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            embed_model = SentenceTransformer("paraphrase-MiniLM-L3-v2")
        print("✅ Semantic search model loaded")
    except Exception as e:
        print(f"⚠️  Embed model failed ({e}) — keyword search fallback")

def load_embed():
    t = threading.Thread(target=_load_embed_sync, daemon=True)
    t.start()

def embed(text: str) -> Optional[List[float]]:
    if embed_model is None:
        return None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
    return embed_model.encode(text, normalize_embeddings=True).tolist()

def _send_push_to_subscription(subscription_json: str, title: str, body: str, data: dict) -> bool:
    if not HAS_WEBPUSH or not VAPID_PRIVATE or not VAPID_PUBLIC:
        return False
    try:
        sub = json.loads(subscription_json)
        webpush(
            subscription_info=sub,
            data=json.dumps({"title": title, "body": body, **data}),
            vapid_private_key=VAPID_PRIVATE,
            vapid_claims={"sub": VAPID_CLAIMS_EMAIL},
        )
        return True
    except WebPushException as e:
        if hasattr(e, "response") and e.response and e.response.status_code == 410:
            return None
        log.debug(f"[PUSH] WebPushException: {e}")
        return False
    except Exception as e:
        log.debug(f"[PUSH] push error: {e}")
        return False

async def send_push_notifications(number: str, title: str, body: str, data: dict = None):
    if not HAS_WEBPUSH or not VAPID_PRIVATE or not VAPID_PUBLIC:
        return
    data = data or {}
    loop = asyncio.get_event_loop()
    with Database() as d:
        rows = d.fetchall(
            "SELECT token FROM device_tokens WHERE owner=? AND platform='webpush'",
            (number,)
        )
    if not rows:
        return
    expired = []
    for row in rows:
        sub_json = row["token"]
        result = await loop.run_in_executor(
            None, _send_push_to_subscription, sub_json, title, body, data
        )
        if result is None:
            expired.append(sub_json)
    if expired:
        with Database() as d:
            for sub_json in expired:
                d.execute(
                    "DELETE FROM device_tokens WHERE owner=? AND token=?",
                    (number, sub_json)
                )
            d.commit()

class WsManager:
    def __init__(self):
        self.active: Dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, number: str, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            old = self.active.get(number)
            if old:
                try: await old.close(code=4000)
                except Exception: pass
            self.active[number] = ws
        with Database() as d:
            d.execute("UPDATE users SET online=1, last_seen=datetime('now') WHERE number=?", (number,))
        await self._broadcast_presence(number, True)

    async def disconnect(self, number: str):
        with Database() as d:
            rows = d.fetchall("SELECT DISTINCT owner FROM contacts WHERE number=?", (number,))
            notify = [r["owner"] for r in rows]
            d.execute("UPDATE users SET online=0, last_seen=datetime('now') WHERE number=?", (number,))
        async with self._lock:
            self.active.pop(number, None)
        ts = datetime.now(timezone.utc).isoformat()
        for c in notify:
            await self.send(c, {"type": "presence", "number": number, "online": False, "last_seen": ts})

    async def send(self, number: str, data: dict) -> bool:
        async with self._lock:
            ws = self.active.get(number)
        if ws:
            try:
                await ws.send_text(json.dumps(data))
                return True
            except Exception:
                return False
        return False

    async def _broadcast_presence(self, number: str, online: bool):
        with Database() as d:
            rows = d.fetchall("SELECT DISTINCT owner FROM contacts WHERE number=?", (number,))
            contacts = [r["owner"] for r in rows]
        payload = {"type": "presence", "number": number, "online": online,
                   "last_seen": datetime.now(timezone.utc).isoformat()}
        for c in contacts:
            await self.send(c, payload)

manager = WsManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _guardian
    init_db()
    run_migrations(DB_PATH)
    _guardian = DataGuardian(DB_PATH)
    _guardian.start()
    load_embed()

    try:
        ip = socket.gethostbyname(socket.gethostname())
        print(f"   Network → http://{ip}:{PORT}")
    except Exception:
        pass
    print(f"   Local   → http://localhost:{PORT}")
    print(f"   DB      → {os.path.abspath(DB_PATH)}")
    print(f"   Backups → auto every {int(os.environ.get('SYNORA_BACKUP_INTERVAL_H', 6))}h")
    print(f"   CORS    → {', '.join(ALLOWED_ORIGINS)}\n")

    yield

    print("\n🔒 Synora shutting down — creating final backup…")
    if _guardian:
        _guardian.stop()
    create_backup(DB_PATH, label="shutdown")
    _db.close()
    print("✅ Final backup saved. Goodbye.\n")

app = FastAPI(lifespan=lifespan, title="Synora", version="2.1.0", docs_url=None, redoc_url=None)

_cors_wildcard = ALLOWED_ORIGINS == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=not _cors_wildcard,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.exception_handler(StarletteHTTPException)
async def http_err(req, exc):
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc.detail)})

@app.exception_handler(RequestValidationError)
async def val_err(req, exc):
    return JSONResponse(status_code=422, content={"detail": str(exc)})

@app.exception_handler(Exception)
async def generic_err(req, exc):
    log.error(f"Unhandled on {req.url.path}: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": f"Server error: {type(exc).__name__}"})

@app.get("/", response_class=HTMLResponse)
async def index():
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Synora</h1><p>templates/index.html not found.</p>", status_code=500)

@app.get("/health")
async def health():
    return {"status": "ok", "app": "Synora", "version": "2.1.0"}

@app.get('/ads.txt')
async def serve_ads_txt():
    return FileResponse(STATIC_DIR / 'ads.txt', media_type='text/plain')

@app.get('/sw.js')
async def serve_sw():
    return FileResponse(
        STATIC_DIR / 'sw.js',
        media_type='application/javascript',
        headers={'Service-Worker-Allowed': '/'}
    )

GOOGLE_SCRIPT = os.environ.get("GOOGLE_SCRIPT_URL", "")

def _log_event(event: str, user: dict, req: Request):
    if not HAS_REQUESTS or not GOOGLE_SCRIPT:
        return
    try:
        _req_lib.post(GOOGLE_SCRIPT, json={
            "event": event, "number": user["number"], "name": user["name"],
            "ip": req.client.host if req.client else "unknown",
            "device": req.headers.get("user-agent", "unknown"),
        }, timeout=4)
    except Exception:
        pass

@app.post("/api/register")
async def register(req: Request):
    client_ip = req.client.host if req.client else "unknown"
    allowed, _ = check_rate_limit(f"register:{client_ip}", max_requests=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, "Too many accounts created from this connection. Try again in an hour.")

    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid request body")

    name       = sanitize_input(data.get("name") or "", max_len=50)
    password   = data.get("password") or ""
    public_key = sanitize_input(data.get("public_key") or "", max_len=8192)

    if not name or len(name) < 2:
        raise HTTPException(400, "Name must be at least 2 characters")
    if len(name) > 50:
        raise HTTPException(400, "Name must be 50 characters or less")
    if not password or len(password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if len(password) > 128:
        raise HTTPException(400, "Password must be 128 characters or less")
    if not public_key:
        raise HTTPException(400, "Public key is required")

    number = await gen_number()
    color  = random.choice(COLORS)

    try:
        hashed = hash_pw(password)
    except Exception as e:
        raise HTTPException(500, f"Hashing error: {e}")

    try:
        with Database() as d:
            d.execute(
                "INSERT INTO users (number, name, password, color, public_key) VALUES (?,?,?,?,?)",
                (number, name, hashed, color, public_key)
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Please try again")
    except Exception as e:
        raise HTTPException(500, f"Database error: {e}")

    audit_event(DB_PATH, number, "register", client_ip, f"name={name}")
    threading.Thread(target=_log_event, args=("register", {"number": number, "name": name}, req), daemon=True).start()

    return {"token": make_token(number), "number": number, "name": name, "color": color, "status": "Hey there! I am using Synora."}

@app.post("/api/login")
async def login(req: Request):
    client_ip = req.client.host if req.client else "unknown"

    if is_blocked(client_ip):
        raise HTTPException(429, "Too many failed attempts. Try again later.")
    allowed, remaining = check_rate_limit(f"login:{client_ip}", max_requests=10, window_seconds=300)
    if not allowed:
        block_ip(client_ip)
        audit_event(DB_PATH, "unknown", "login_rate_blocked", client_ip, "Blocked after repeated failures")
        raise HTTPException(429, "Too many login attempts. Please wait 5 minutes.")

    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid request body")

    raw    = str(data.get("number") or "")
    number = "".join(filter(str.isdigit, raw))
    pw     = data.get("password") or ""

    if not number or not pw:
        raise HTTPException(400, "Synora number and password are required")
    if len(number) < 7 or len(number) > 10:
        raise HTTPException(401, "Incorrect number or password")
    if len(pw) > 128:
        raise HTTPException(401, "Incorrect number or password")

    with Database() as d:
        user = d.fetchone("SELECT * FROM users WHERE number=?", (number,))
        if not user and len(number) < 7:
            user = d.fetchone("SELECT * FROM users WHERE number=?", (number.zfill(7),))

    if not user or not verify_pw(pw, user["password"]):
        audit_event(DB_PATH, number or "unknown", "login_failed", client_ip, "Wrong credentials")
        raise HTTPException(401, "Incorrect number or password")

    audit_event(DB_PATH, user["number"], "login_ok", client_ip)
    threading.Thread(target=_log_event, args=("login", {"number": user["number"], "name": user["name"]}, req), daemon=True).start()

    return {
        "token":  make_token(user["number"]),
        "number": user["number"],
        "name":   user["name"],
        "color":  user["color"],
        "status": user["status"]
    }

@app.get("/api/turn-credentials")
async def get_turn_credentials(number: str = Depends(get_current_user)):
    username = os.environ.get("METERED_USERNAME", "")
    password = os.environ.get("METERED_PASSWORD", "")
    if not username or not password:
        return JSONResponse({"username": "", "credential": ""}, status_code=200)
    return {"username": username, "credential": password}

@app.get("/api/me")
async def me(number: str = Depends(get_current_user)):
    with Database() as d:
        user = d.fetchone("SELECT number,name,color,status,last_seen FROM users WHERE number=?", (number,))
    if not user:
        raise HTTPException(404, "User not found")
    return dict(user)

@app.put("/api/me/status")
async def update_status(req: Request, number: str = Depends(get_current_user)):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid body")
    status = sanitize_input(data.get("status") or "", max_len=120)
    with Database() as d:
        d.execute("UPDATE users SET status=? WHERE number=?", (status, number))
    return {"ok": True}

def _find_user(d: Database, target: str):
    clean = "".join(filter(str.isdigit, target))
    if not clean:
        return None
    user = d.fetchone(
        "SELECT number,name,color,public_key,status,online,last_seen FROM users WHERE number=?", (clean,)
    )
    if not user and len(clean) < 7:
        user = d.fetchone(
            "SELECT number,name,color,public_key,status,online,last_seen FROM users WHERE number=?", (clean.zfill(7),)
        )
    return user

@app.get("/api/user/{target}")
async def get_user(target: str, number: str = Depends(get_current_user)):
    with Database() as d:
        user = _find_user(d, target)
    if not user:
        raise HTTPException(404, "No Synora user found with that number.")
    return dict(user)

@app.get("/api/lookup")
async def lookup(q: str = Query(..., min_length=1), number: str = Depends(get_current_user)):
    digits = "".join(filter(str.isdigit, q))
    if not digits:
        return []
    with Database() as d:
        exact = d.fetchone(
            "SELECT number,name,color,online,last_seen FROM users WHERE number=? AND number!=?", (digits, number)
        )
        if not exact and len(digits) < 7:
            exact = d.fetchone(
                "SELECT number,name,color,online,last_seen FROM users WHERE number=? AND number!=?",
                (digits.zfill(7), number)
            )
        partial = d.fetchall(
            "SELECT number,name,color,online,last_seen FROM users WHERE number LIKE ? AND number!=? LIMIT 6",
            (digits + "%", number)
        ) if not exact else []

    seen, results = set(), []
    for u in ([exact] if exact else []) + list(partial):
        if u and u["number"] not in seen:
            seen.add(u["number"])
            results.append(dict(u))
    return results

@app.get("/api/contacts")
async def get_contacts(number: str = Depends(get_current_user)):
    with Database() as d:
        rows = d.fetchall("""
            SELECT ct.number, ct.saved_name, u.color, u.online, u.last_seen, u.status,
                   (SELECT content FROM messages
                    WHERE (sender=? AND receiver=ct.number) OR (sender=ct.number AND receiver=?)
                    ORDER BY ts DESC LIMIT 1) AS last_msg,
                   (SELECT ts FROM messages
                    WHERE (sender=? AND receiver=ct.number) OR (sender=ct.number AND receiver=?)
                    ORDER BY ts DESC LIMIT 1) AS last_ts,
                   (SELECT COUNT(*) FROM messages
                    WHERE sender=ct.number AND receiver=? AND status!='read') AS unread
            FROM contacts ct JOIN users u ON ct.number=u.number
            WHERE ct.owner=?
            ORDER BY last_ts DESC NULLS LAST, ct.saved_name ASC
        """, (number, number, number, number, number, number))

    result = []
    for r in rows:
        row = dict(r)
        if row.get("last_msg"):
            try:
                row["last_msg"] = decrypt_content(row["last_msg"])
            except Exception:
                row["last_msg"] = "🔒 Message"
        result.append(row)
    return result

@app.post("/api/contacts")
async def add_contact(req: Request, number: str = Depends(get_current_user)):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid body")

    raw_target = str(data.get("number") or "")
    saved_name = sanitize_input(data.get("name") or "", max_len=50)
    target     = "".join(filter(str.isdigit, raw_target))

    if not target:
        raise HTTPException(400, "A valid Synora number is required")
    if not saved_name:
        raise HTTPException(400, "A name is required")
    if target == number:
        raise HTTPException(400, "You cannot add yourself as a contact")

    with Database() as d:
        user = _find_user(d, target)
        if not user:
            raise HTTPException(404, f"No Synora user found with number {target}.")
        canonical = user["number"]
        d.execute(
            "INSERT OR REPLACE INTO contacts (owner, number, saved_name) VALUES (?,?,?)",
            (number, canonical, saved_name)
        )

    return {"number": user["number"], "saved_name": saved_name, "color": user["color"], "status": user["status"]}

@app.delete("/api/contacts/{target}")
async def del_contact(target: str, number: str = Depends(get_current_user)):
    with Database() as d:
        d.execute("DELETE FROM contacts WHERE owner=? AND number=?", (number, target))
    return {"ok": True}

MSG_MAX_LEN = int(os.environ.get("SYNORA_MSG_MAX_LEN", "8000"))

@app.get("/api/messages/{peer}")
async def get_messages(peer: str, number: str = Depends(get_current_user), before: Optional[str] = None):
    with Database() as d:
        if before:
            rows = d.fetchall("""
                SELECT * FROM messages
                WHERE ((sender=? AND receiver=?) OR (sender=? AND receiver=?)) AND ts < ?
                  AND deleted=0
                ORDER BY ts DESC LIMIT 60
            """, (number, peer, peer, number, before))
        else:
            rows = d.fetchall("""
                SELECT * FROM messages
                WHERE ((sender=? AND receiver=?) OR (sender=? AND receiver=?))
                  AND deleted=0
                ORDER BY ts DESC LIMIT 60
            """, (number, peer, peer, number))
        d.execute(
            "UPDATE messages SET status='read' WHERE sender=? AND receiver=? AND status!='read'",
            (peer, number)
        )

    result = []
    for r in rows:
        row = dict(r)
        try:
            row["content"] = decrypt_content(row["content"])
        except Exception:
            pass
        result.append(row)
    return list(reversed(result))

@app.delete("/api/messages/{msg_id}")
async def delete_message(msg_id: str, number: str = Depends(get_current_user)):
    with Database() as d:
        msg = d.fetchone("SELECT sender FROM messages WHERE msg_id=?", (msg_id,))
        if not msg:
            raise HTTPException(404, "Message not found")
        if msg["sender"] != number:
            raise HTTPException(403, "You can only delete your own messages")
        d.execute(
            "UPDATE messages SET deleted=1, deleted_at=datetime('now') WHERE msg_id=?",
            (msg_id,)
        )
    return {"ok": True}

@app.get("/api/call-logs")
async def call_logs(number: str = Depends(get_current_user)):
    with Database() as d:
        rows = d.fetchall("""
            SELECT cl.*, u.name, u.color
            FROM call_logs cl
            JOIN users u ON (CASE WHEN cl.caller=? THEN cl.callee ELSE cl.caller END) = u.number
            WHERE cl.caller=? OR cl.callee=?
            ORDER BY cl.ts DESC LIMIT 100
        """, (number, number, number))
    return [dict(r) for r in rows]

@app.get("/api/search")
async def search(q: str = Query(..., min_length=1, max_length=200), number: str = Depends(get_current_user)):
    if not HAS_NUMPY or embed_model is None:
        with Database() as d:
            rows = d.fetchall("""
                SELECT msg_id, sender, receiver, content, ts FROM messages
                WHERE (sender=? OR receiver=?) AND deleted=0
                ORDER BY ts DESC LIMIT 200
            """, (number, number))
        results = []
        ql = q.lower()
        for r in rows:
            row = dict(r)
            try:
                plain = decrypt_content(row["content"])
            except Exception:
                plain = row["content"]
            if ql in plain.lower():
                row["content"] = plain
                results.append(row)
            if len(results) >= 30:
                break
        return results

    q_emb = embed(q)
    if q_emb is None:
        raise HTTPException(500, "Search unavailable")
    q_arr = np.array(q_emb, dtype=np.float32)

    with Database() as d:
        rows = d.fetchall("""
            SELECT m.msg_id, m.sender, m.receiver, m.content, m.ts, me.embedding
            FROM messages m JOIN message_embeddings me ON m.msg_id=me.msg_id
            WHERE (m.sender=? OR m.receiver=?) AND m.deleted=0
        """, (number, number))

    if not rows:
        return []

    sims = []
    for r in rows:
        try:
            plain = decrypt_content(r["content"])
            e = np.frombuffer(r["embedding"], dtype=np.float32)
            s = float(np.dot(q_arr, e))
            sims.append((s, dict(r), plain))
        except Exception:
            continue

    sims.sort(key=lambda x: x[0], reverse=True)
    return [
        {"msg_id": s[1]["msg_id"], "sender": s[1]["sender"], "receiver": s[1]["receiver"],
         "content": s[2], "ts": s[1]["ts"], "score": round(s[0], 4)}
        for s in sims[:20] if s[0] > 0.3
    ]

@app.websocket("/ws/{token_str}")
async def ws_endpoint(ws: WebSocket, token_str: str):
    number = decode_token(token_str)
    if not number:
        await ws.close(code=4001)
        return

    with Database() as d:
        if not d.fetchone("SELECT 1 FROM users WHERE number=?", (number,)):
            await ws.close(code=4001)
            return

    await manager.connect(number, ws)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                continue

            mtype = data.get("type")

            if mtype == "message":
                receiver = sanitize_input(data.get("to") or "", max_len=10)
                content  = (data.get("content") or "").strip()
                if not receiver or not content:
                    continue
                if len(content) > MSG_MAX_LEN * 6:
                    continue

                msg_id = str(uuid.uuid4())
                ts     = datetime.now(timezone.utc).isoformat()
                stored_content = encrypt_content(content)

                with Database() as d:
                    d.execute(
                        "INSERT INTO messages (msg_id, sender, receiver, content, status, ts) VALUES (?,?,?,?,?,?)",
                        (msg_id, number, receiver, stored_content, "sent", ts)
                    )
                    if embed_model:
                        try:
                            emb = embed_model.encode(content, normalize_embeddings=True).tobytes()
                            d.execute(
                                "INSERT OR IGNORE INTO message_embeddings (msg_id, embedding) VALUES (?,?)",
                                (msg_id, emb)
                            )
                        except Exception:
                            pass

                delivered = receiver in manager.active
                status    = "delivered" if delivered else "sent"

                payload = {
                    "type": "message", "msg_id": msg_id,
                    "from": number, "from_name": data.get("from_name", ""),
                    "content": content,
                    "ts": ts, "status": status
                }
                await manager.send(receiver, payload)
                await manager.send(number, {"type": "message_ack", "msg_id": msg_id, "status": status, "ts": ts})

                if not delivered:
                    sender_name = data.get("from_name") or number
                    preview = content if len(content) <= 60 else content[:57] + "…"
                    asyncio.create_task(send_push_notifications(
                        receiver,
                        title=f"New message from {sender_name}",
                        body=preview,
                        data={"msg_id": msg_id, "from": number},
                    ))

            elif mtype == "typing":
                target = sanitize_input(data.get("to") or "", max_len=10)
                if target:
                    await manager.send(target, {"type": "typing", "from": number, "typing": bool(data.get("typing"))})

            elif mtype == "read":
                peer = sanitize_input(data.get("from") or "", max_len=10)
                if peer:
                    with Database() as d:
                        d.execute(
                            "UPDATE messages SET status='read' WHERE sender=? AND receiver=? AND status!='read'",
                            (peer, number)
                        )
                    await manager.send(peer, {"type": "read", "by": number})

            elif mtype in ("call_offer", "call_answer", "ice_candidate", "call_reject", "call_end", "call_ring"):
                target = sanitize_input(data.get("to") or "", max_len=10)
                data["from"] = number
                if target:
                    await manager.send(target, data)

                if mtype == "call_offer":
                    cid = sanitize_input(data.get("call_id") or str(uuid.uuid4()), max_len=40)
                    with Database() as d:
                        d.execute(
                            "INSERT OR IGNORE INTO call_logs (call_id,caller,callee,call_type,status,ts) VALUES (?,?,?,?,'ringing',datetime('now'))",
                            (cid, number, target, data.get("call_type", "voice"))
                        )
                    if target and target not in manager.active:
                        call_type = data.get("call_type", "voice")
                        label = "📞 Incoming voice call" if call_type == "voice" else "📹 Incoming video call"
                        asyncio.create_task(send_push_notifications(
                            target,
                            title=label,
                            body=f"From {number}",
                            data={"call_id": cid, "call_type": call_type, "from": number},
                        ))
                elif mtype == "call_end":
                    cid = sanitize_input(data.get("call_id") or "", max_len=40)
                    if cid:
                        with Database() as d:
                            d.execute(
                                "UPDATE call_logs SET status='ended', duration=? WHERE call_id=?",
                                (int(data.get("duration", 0)), cid)
                            )
                elif mtype == "call_reject":
                    cid = sanitize_input(data.get("call_id") or "", max_len=40)
                    if cid:
                        with Database() as d:
                            d.execute("UPDATE call_logs SET status='rejected' WHERE call_id=?", (cid,))

            elif mtype == "ping":
                await manager.send(number, {"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.debug(f"[WS] {number}: {e}")
    finally:
        await manager.disconnect(number)

@app.get("/api/me/export")
async def export_my_data(number: str = Depends(get_current_user)):
    allowed, _ = check_rate_limit(f"export:{number}", max_requests=3, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, "Export rate limit reached. Try again in an hour.")
    data = export_user_data(DB_PATH, number, decrypt_fn=decrypt_content)
    audit_event(DB_PATH, number, "data_export", "", "User requested full data export")
    return JSONResponse(content=data, headers={
        "Content-Disposition": f'attachment; filename="synora_export_{number}.json"'
    })

@app.delete("/api/me")
async def delete_my_account(req: Request, number: str = Depends(get_current_user)):
    create_backup(DB_PATH, label=f"pre_delete_{number}")
    with Database() as d:
        d.execute("DELETE FROM contacts WHERE owner=? OR number=?", (number, number))
        d.execute("DELETE FROM messages WHERE sender=? OR receiver=?", (number, number))
        d.execute("DELETE FROM call_logs WHERE caller=? OR callee=?", (number, number))
        d.execute("DELETE FROM message_embeddings WHERE msg_id NOT IN (SELECT msg_id FROM messages)")
        d.execute("DELETE FROM users WHERE number=?", (number,))
    audit_event(DB_PATH, number, "account_deleted", req.client.host if req.client else "", "Self-deletion")
    return {"ok": True, "message": "Your account and all associated data have been permanently deleted."}

@app.get("/api/admin/backups")
async def list_backup_files(
    req: Request,
    admin_key: str = Query(..., alias="key"),
    number: str = Depends(get_current_user)
):
    expected = os.environ.get("SYNORA_ADMIN_KEY", "")
    if not expected or not hmac.compare_digest(admin_key, expected):
        raise HTTPException(403, "Invalid admin key")
    return {"backups": list_backups(DB_PATH), "count": len(list_backups(DB_PATH))}

@app.post("/api/admin/backup")
async def trigger_backup(
    req: Request,
    admin_key: str = Query(..., alias="key"),
    number: str = Depends(get_current_user)
):
    expected = os.environ.get("SYNORA_ADMIN_KEY", "")
    if not expected or not hmac.compare_digest(admin_key, expected):
        raise HTTPException(403, "Invalid admin key")
    result = create_backup(DB_PATH, label="manual")
    if result:
        return {"ok": True, "file": result.name, "path": str(result)}
    raise HTTPException(500, "Backup failed — check server logs")

@app.get("/api/admin/integrity")
async def check_integrity(
    admin_key: str = Query(..., alias="key"),
    number: str = Depends(get_current_user)
):
    expected = os.environ.get("SYNORA_ADMIN_KEY", "")
    if not expected or not hmac.compare_digest(admin_key, expected):
        raise HTTPException(403, "Invalid admin key")
    ok, details = run_integrity_check(DB_PATH)
    return {"ok": ok, "details": details}

@app.get("/api/admin/audit")
async def get_audit_log(
    admin_key: str = Query(..., alias="key"),
    number: str = Depends(get_current_user),
    limit: int = Query(default=100, le=500)
):
    expected = os.environ.get("SYNORA_ADMIN_KEY", "")
    if not expected or not hmac.compare_digest(admin_key, expected):
        raise HTTPException(403, "Invalid admin key")
    with Database() as d:
        rows = d.fetchall("SELECT * FROM user_audit ORDER BY ts DESC LIMIT ?", (limit,))
    return {"events": [dict(r) for r in rows]}

import secrets as _secrets

_otp_store: Dict[str, dict] = {}
_otp_lock = threading.Lock()

def _cleanup_otps():
    now = datetime.now(timezone.utc)
    with _otp_lock:
        expired = [k for k, v in _otp_store.items()
                   if datetime.fromisoformat(v["expires"]) < now]
        for k in expired:
            del _otp_store[k]

def _send_otp_email(email: str, code: str):
    smtp_host = os.environ.get("SMTP_HOST", "")
    if smtp_host:
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(
                f"Your Synora verification code is: {code}\n\n"
                f"It expires in 10 minutes. Do not share it with anyone.",
                "plain"
            )
            msg["Subject"] = f"Synora verification code: {code}"
            msg["From"]    = os.environ.get("SMTP_FROM", "noreply@synora.app")
            msg["To"]      = email
            port = int(os.environ.get("SMTP_PORT", 587))
            with smtplib.SMTP(smtp_host, port) as s:
                s.starttls()
                s.login(os.environ.get("SMTP_USER", ""), os.environ.get("SMTP_PASS", ""))
                s.send_message(msg)
            log.info(f"[otp] Sent to {email[:3]}***")
        except Exception as e:
            log.error(f"[otp] SMTP failed: {e}")
    else:
        print(f"\n📧 OTP for {email}: {code}  (configure SMTP_HOST to send real emails)\n")

@app.post("/api/register/otp/send")
async def otp_send(req: Request):
    client_ip = req.client.host if req.client else "unknown"
    allowed, _ = check_rate_limit(f"otp:{client_ip}", max_requests=5, window_seconds=600)
    if not allowed:
        raise HTTPException(429, "Too many OTP requests. Try again in 10 minutes.")
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid request body")

    email = sanitize_input(data.get("email") or "", max_len=254).lower()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(400, "A valid email address is required")

    code    = str(_secrets.randbelow(900000) + 100000)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

    with _otp_lock:
        _otp_store[email] = {"code": code, "expires": expires, "attempts": 0}

    threading.Thread(target=_send_otp_email, args=(email, code), daemon=True).start()
    audit_event(DB_PATH, "anon", "otp_sent", client_ip, f"email={email[:3]}***")
    return {"ok": True, "message": "Verification code sent"}

@app.post("/api/register/otp/verify")
async def otp_verify(req: Request):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid request body")

    email = sanitize_input(data.get("email") or "", max_len=254).lower()
    code  = sanitize_input(data.get("code")  or "", max_len=10)

    if not email or not code:
        raise HTTPException(400, "Email and code are required")

    _cleanup_otps()

    with _otp_lock:
        entry = _otp_store.get(email)
        if not entry:
            raise HTTPException(400, "No pending verification for this email. Request a new code.")

        entry["attempts"] = entry.get("attempts", 0) + 1
        if entry["attempts"] > 5:
            del _otp_store[email]
            raise HTTPException(429, "Too many incorrect attempts. Request a new code.")

        if datetime.fromisoformat(entry["expires"]) < datetime.now(timezone.utc):
            del _otp_store[email]
            raise HTTPException(400, "Code expired. Request a new one.")

        if not hmac.compare_digest(entry["code"], code):
            raise HTTPException(400, f"Incorrect code. {5 - entry['attempts']} attempts remaining.")

        del _otp_store[email]

    verified_payload = {
        "sub": f"otp:{email}",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
        "type": "otp_verified",
    }
    verified_token = jwt.encode(verified_payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"ok": True, "verified_token": verified_token}

@app.get("/api/me/key-backup")
async def get_key_backup(number: str = Depends(get_current_user)):
    with Database() as d:
        row = d.fetchone("SELECT key_backup FROM users WHERE number=?", (number,))
    if not row or not row["key_backup"]:
        raise HTTPException(404, "No key backup found on server")
    return {"key_backup": row["key_backup"], "number": number}

@app.put("/api/me/key-backup")
async def put_key_backup(req: Request, number: str = Depends(get_current_user)):
    allowed, _ = check_rate_limit(f"keybk:{number}", max_requests=10, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, "Key backup rate limit reached")
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid body")

    key_backup = sanitize_input(data.get("key_backup") or "", max_len=16384)
    if not key_backup:
        raise HTTPException(400, "key_backup is required")

    try:
        with Database() as d:
            d.execute("UPDATE users SET key_backup=? WHERE number=?", (key_backup, number))
    except Exception:
        raise HTTPException(500, "Failed to save key backup")

    audit_event(DB_PATH, number, "key_backup_updated", "", "User updated encrypted key backup")
    return {"ok": True}

@app.delete("/api/me/key-backup")
async def delete_key_backup(number: str = Depends(get_current_user)):
    with Database() as d:
        d.execute("UPDATE users SET key_backup=NULL WHERE number=?", (number,))
    audit_event(DB_PATH, number, "key_backup_deleted", "", "User removed key backup")
    return {"ok": True}

@app.post("/api/report")
async def submit_report(req: Request, number: str = Depends(get_current_user)):
    allowed, _ = check_rate_limit(f"report:{number}", max_requests=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, "Report rate limit reached. Try again later.")
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid body")

    reported_number = sanitize_input(data.get("reported_number") or "", max_len=10)
    reason          = sanitize_input(data.get("reason") or "", max_len=50)
    details         = sanitize_input(data.get("details") or "", max_len=500)
    msg_id          = sanitize_input(data.get("msg_id") or "", max_len=40)

    VALID_REASONS = {"spam", "harassment", "inappropriate_content", "fake_account", "other"}
    if reason not in VALID_REASONS:
        raise HTTPException(400, f"Reason must be one of: {', '.join(VALID_REASONS)}")
    if not reported_number:
        raise HTTPException(400, "reported_number is required")

    with Database() as d:
        d.execute(
            """INSERT INTO abuse_reports (reporter, reported, reason, details, msg_id)
               VALUES (?,?,?,?,?)""",
            (number, reported_number, reason, details, msg_id or None)
        )
    audit_event(DB_PATH, number, "abuse_report",
                req.client.host if req.client else "",
                f"reported={reported_number} reason={reason}")
    return {"ok": True, "message": "Report submitted. Thank you for helping keep Synora safe."}

@app.get("/api/push/vapid-public-key")
async def get_vapid_public_key():
    if not VAPID_PUBLIC:
        raise HTTPException(503, "Push notifications not configured on this server")
    return {"publicKey": VAPID_PUBLIC}

@app.post("/api/push/subscribe")
async def push_subscribe(req: Request, number: str = Depends(get_current_user)):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid body")

    subscription_json = json.dumps(data.get("subscription") or {})
    if len(subscription_json) > 4096:
        raise HTTPException(400, "Subscription payload too large")

    with Database() as d:
        d.execute(
            """INSERT INTO device_tokens (owner, token, platform)
               VALUES (?,?,?)
               ON CONFLICT(owner, token) DO NOTHING""",
            (number, subscription_json, "webpush")
        )
    return {"ok": True}

@app.delete("/api/push/unsubscribe")
async def push_unsubscribe(req: Request, number: str = Depends(get_current_user)):
    try:
        data = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid body")
    token = json.dumps(data.get("subscription") or {})
    with Database() as d:
        d.execute("DELETE FROM device_tokens WHERE owner=? AND token=?", (number, token))
    return {"ok": True}

def start(port: int = None):
    _port = port or PORT
    config = uvicorn.Config(app, host="0.0.0.0", port=_port, log_level="warning")
    server = uvicorn.Server(config)

    try:
        loop = asyncio.get_running_loop()
        print(f"\n✨ Synora v2.1 starting (Colab/Jupyter) on port {_port}…\n")
        try:
            import nest_asyncio
            nest_asyncio.apply(loop)
        except ImportError:
            pass
        loop.run_until_complete(server.serve())
    except RuntimeError:
        print(f"\n✨ Synora v2.1 starting on port {_port}…\n")
        asyncio.run(server.serve())

if __name__ == "__main__":
    _port = PORT
    if not os.environ.get("PORT"):
        s = socket.socket(); s.bind(("", 0)); _port = s.getsockname()[1]; s.close()
    start(_port)
