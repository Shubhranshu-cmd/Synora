<div align="center">

<img src="static/icons/icon-192.svg" width="96" height="96" alt="Synora Logo" />

# Synora

**Private encrypted messaging & calling — no phone number required**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-7C3AED?style=flat-square)](#license)
[![PWA Ready](https://img.shields.io/badge/PWA-Ready-5A0FC8?style=flat-square&logo=pwa&logoColor=white)](#android-apk)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=flat-square&logo=docker&logoColor=white)](#docker-recommended)

*Built by [Shubhranshu](mailto:yshubhranshu746@gmail.com)*

</div>

---

## What is Synora?

Synora is a self-hosted, open-source messaging platform. Users sign up with just a name and password — no phone number, no email required. Every account gets a unique **Synora Number** (like a private ID). Messages are encrypted with AES-256-GCM before they ever touch the database.

It runs as a single Python server you can deploy in minutes on Railway, Render, or your own VPS — and wrap into an Android APK or iOS app via PWABuilder with no extra code.

---

## Features

| Feature | Details |
|---|---|
| 🔐 **Encrypted messages** | AES-256-GCM at rest, Argon2 passwords |
| 📞 **Voice & video calls** | WebRTC peer-to-peer via WebSocket signaling |
| 🔔 **Push notifications** | Real Web Push (VAPID) — works when app is closed |
| 🔍 **Semantic search** | AI-powered message search (sentence-transformers) |
| 👤 **No phone number** | Synora Number system — fully anonymous identity |
| 📱 **PWA / installable** | Works as Android APK, iOS app, or desktop app |
| 🛡️ **Rate limiting & audit** | IP blocking, audit log, admin backup API |
| 🗄️ **Auto backups** | SQLite with scheduled backups and one-click restore |
| 📤 **Data export** | Users can export all their data (GDPR-friendly) |
| 🐳 **Docker ready** | One command deploy with `docker compose up` |

---

## Tech Stack

```
Backend   →  Python 3.10+, FastAPI, SQLite, WebSockets
Security  →  AES-256-GCM, Argon2, JWT (HS256), pywebpush (VAPID)
AI        →  sentence-transformers (paraphrase-MiniLM-L3-v2)
Frontend  →  Vanilla JS, CSS, PWA (manifest + service worker)
Calling   →  WebRTC (ICE/SDP signaled over WebSocket)
Deploy    →  Docker, Railway, Render, VPS
```

---

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/YOUR_USERNAME/synora.git
cd synora
cp .env.example .env
# Edit .env with your values (see Environment Variables below)
docker compose up -d
```

Visit `http://localhost:80`

---

### Manual (Python)

```bash
git clone https://github.com/YOUR_USERNAME/synora.git
cd synora
pip install -r requirements.txt
cp .env.example .env
# Edit .env
python app.py
```

Visit `http://localhost:8080`

---

### Deploy Free on Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → **New Project → Deploy from GitHub**
3. Select your repo
4. Set environment variables from `.env.example` in the Railway dashboard
5. Railway gives you a free `https://yourapp.up.railway.app` URL with HTTPS

---

## Environment Variables

Copy `.env.example` to `.env` and fill in these values:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing secret — 32+ random characters |
| `MSG_ENC_KEY` | ✅ | AES-256 message key — 64-char hex string |
| `VAPID_PRIVATE` | ✅ for push | VAPID private key for Web Push |
| `VAPID_PUBLIC` | ✅ for push | VAPID public key for Web Push |
| `VAPID_CLAIMS_EMAIL` | ✅ for push | `mailto:you@example.com` |
| `SMTP_HOST` | Optional | SMTP server for OTP email verification |
| `SMTP_USER` | Optional | SMTP username |
| `SMTP_PASS` | Optional | SMTP app password |
| `SYNORA_ADMIN_KEY` | Optional | API key for admin endpoints |
| `SYNORA_ORIGINS` | Optional | Comma-separated allowed CORS origins |
| `SYNORA_BACKUP_INTERVAL_H` | Optional | Backup frequency in hours (default: 6) |

### Generating VAPID Keys

Run this once in your server terminal (or Railway shell):

```bash
python -c "
from py_vapid import Vapid
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
v = Vapid()
v.generate_keys()
print('VAPID_PRIVATE=' + v.private_pem().decode())
print('VAPID_PUBLIC=' + v.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
"
```

Paste the output into your `.env` file.

---

## Android APK

Synora is a full PWA (Progressive Web App) — no Android Studio or Xcode required.

1. Deploy Synora to Railway (or any HTTPS URL)
2. Go to **[pwabuilder.com](https://pwabuilder.com)**
3. Paste your URL → click **Start**
4. Click **Android** → **Download Package**
5. You get a signed APK ready to install or publish to Google Play

> Your app already has a `manifest.json` and service worker — PWABuilder will show all green.

---

## API Reference

All authenticated endpoints require `Authorization: Bearer <token>` header.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/register` | No | Create account |
| `POST` | `/api/login` | No | Login, get JWT |
| `GET` | `/api/me` | Yes | Get your profile |
| `PUT` | `/api/me/status` | Yes | Update status message |
| `GET` | `/api/lookup` | Yes | Find user by Synora Number |
| `GET` | `/api/contacts` | Yes | List contacts |
| `POST` | `/api/contacts` | Yes | Add contact |
| `DELETE` | `/api/contacts/{target}` | Yes | Remove contact |
| `GET` | `/api/messages/{peer}` | Yes | Load message history |
| `DELETE` | `/api/messages/{msg_id}` | Yes | Delete a message |
| `GET` | `/api/call-logs` | Yes | Get call history |
| `GET` | `/api/search` | Yes | Semantic message search |
| `GET` | `/api/me/export` | Yes | Export all your data |
| `DELETE` | `/api/me` | Yes | Delete account |
| `POST` | `/api/report` | Yes | Report a user |
| `GET` | `/api/push/vapid-public-key` | No | Fetch VAPID public key |
| `POST` | `/api/push/subscribe` | Yes | Register push subscription |
| `DELETE` | `/api/push/unsubscribe` | Yes | Remove push subscription |
| `WS` | `/ws/{token}` | Token | Real-time messages & calls |

### Admin Endpoints (require `SYNORA_ADMIN_KEY`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/admin/backups` | List backups |
| `POST` | `/api/admin/backup` | Trigger manual backup |
| `GET` | `/api/admin/integrity` | Run DB integrity check |
| `GET` | `/api/admin/audit` | View audit log |

---

## WebSocket Events

Connect to `wss://yourdomain/ws/<jwt_token>` for real-time features.

**Send (client → server):**

```json
{ "type": "message",    "to": "1234567", "content": "Hello!" }
{ "type": "typing",     "to": "1234567", "typing": true }
{ "type": "read",       "from": "1234567" }
{ "type": "call_offer", "to": "1234567", "call_id": "uuid", "call_type": "voice", "sdp": "..." }
{ "type": "ice_candidate", "to": "1234567", "candidate": "..." }
{ "type": "call_answer",   "to": "1234567", "sdp": "..." }
{ "type": "call_end",      "to": "1234567", "call_id": "uuid", "duration": 42 }
{ "type": "ping" }
```

**Receive (server → client):**

```json
{ "type": "message",      "msg_id": "...", "from": "...", "content": "...", "ts": "...", "status": "delivered" }
{ "type": "message_ack",  "msg_id": "...", "status": "delivered" }
{ "type": "typing",       "from": "...", "typing": true }
{ "type": "read",         "by": "..." }
{ "type": "presence",     "number": "...", "online": true }
{ "type": "pong" }
```

---

## Project Structure

```
synora/
├── app.py              # FastAPI server — all routes, WebSocket, push logic
├── persistence.py      # SQLite helpers, migrations, backups, DataGuardian
├── requirements.txt    # Python dependencies
├── Dockerfile          # Container build
├── docker-compose.yml  # One-command deploy
├── nginx.conf          # Reverse proxy config
├── .env.example        # Environment variable template
├── templates/
│   └── index.html      # Single-page app shell
└── static/
    ├── manifest.json   # PWA manifest
    ├── sw.js           # Service worker (offline + push)
    ├── css/
    │   └── synora.css  # All styles
    ├── js/
    │   └── synora.js   # All frontend logic
    └── icons/
        ├── icon-192.svg
        └── icon-512.svg
```

---

## Security

- Passwords hashed with **Argon2** (winner of the Password Hashing Competition)
- Messages encrypted with **AES-256-GCM** before SQLite storage — server cannot read plaintext
- JWTs signed with **HS256**, 7-day expiry
- Rate limiting and IP blocking on all auth endpoints
- Full audit log of security events
- Input sanitization on all user-supplied fields
- Push notifications signed with **VAPID** (no third-party push service)

---

## Monetization (Ads)

To add Google AdSense to the web version:

1. Sign up at [adsense.google.com](https://adsense.google.com) — free
2. Add your deployed URL and get approved
3. Paste the AdSense `<script>` snippet into `templates/index.html` before `</head>`
4. Ads appear automatically — you earn per impression and click

For the Android APK on Google Play, use **Google AdMob** (free) inside the TWA wrapper for in-app ad revenue.

---

## License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

## Author

Built by **Shubhranshu** — [yshubhranshu746@gmail.com](mailto:yshubhranshu746@gmail.com)

If you use Synora or build on it, a ⭐ on GitHub is appreciated.
