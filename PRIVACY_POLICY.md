# Synora Privacy Policy

**Effective Date:** June 28, 2026  
**App Name:** Synora  
**Developer:** Shubhranshu  
**Contact:** yshubhranshu746@gmail.com

---

## 1. Introduction

Synora ("we", "our", "the app") is a private, end-to-end encrypted messaging and calling application. We are committed to protecting your privacy. This policy explains what data we collect, how we use it, and your rights regarding it.

---

## 2. Data We Collect

### Account Data
- **Display name** — chosen by you at registration
- **Synora number** — automatically generated unique identifier (not your phone number)
- **Password** — stored as a one-way hash (Argon2/SHA-256). We cannot recover it.
- **Profile color** — randomly assigned
- **Status message** — set by you

### Messages
- All message content is **encrypted with AES-256-GCM** before storage
- The server stores ciphertext only; plaintext messages are never logged
- Messages are stored to enable delivery when you are offline

### Call Logs
- Call type (voice/video), participants, timestamp, duration, and status (connected/missed/rejected)
- No audio or video is recorded or stored

### Technical Data
- IP addresses — used for rate-limiting, abuse prevention, and security audit logs
- Device user-agent — used for abuse prevention only
- Connection timestamps — last seen / online status

### Optional Data (if you use these features)
- **Email address** — only if you request OTP-based email verification; not stored permanently after verification
- **Web Push subscription** — if you enable browser push notifications
- **Encrypted key backup** — an encrypted copy of your cryptographic private key, protected by your password; we cannot decrypt it

---

## 3. Data We Do NOT Collect

- We do not collect your phone number
- We do not read your messages (they are encrypted)
- We do not sell your data to third parties
- We do not use your data for advertising profiling
- We do not share your data with data brokers

---

## 4. How We Use Your Data

| Purpose | Data Used |
|---------|-----------|
| Delivering messages | Sender/receiver numbers, encrypted content |
| Account authentication | Synora number, password hash, JWT tokens |
| Security & rate limiting | IP address, login attempt counts |
| Abuse prevention | IP blocks, audit logs, abuse reports |
| OTP verification (optional) | Email address (discarded after use) |
| Service health & debugging | Server logs (no message content) |

---

## 5. Data Retention

- **Messages:** Retained until you delete them or delete your account
- **Call logs:** Retained for 90 days, or until account deletion
- **Audit logs:** Retained for 30 days for security purposes
- **Database backups:** Auto-created every 6 hours, kept for 30 days
- **Blocked IPs:** Retained until the block expires or is manually removed
- **OTP codes:** Expire after 10 minutes and are deleted immediately after use

---

## 6. Data Security

- Passwords are hashed using **Argon2** (industry best practice)
- Messages are encrypted at rest with **AES-256-GCM**
- All API endpoints use **JWT authentication**
- Rate limiting protects against brute-force attacks
- IP-based blocks prevent repeated abuse
- Database uses WAL mode with integrity checks
- All connections should be served over HTTPS in production

---

## 7. Third-Party Services

Synora may optionally integrate with:

| Service | Purpose | Data Shared |
|---------|---------|-------------|
| Google Fonts | UI fonts | None (loaded from CDN) |
| Cloudflare Tunnel | Public URL tunneling | IP, HTTP metadata |
| SMTP Provider (configurable) | OTP email delivery | Email address, OTP code |
| Google Apps Script (optional) | Analytics webhook | Synora number, name, IP, user agent |

The Google Apps Script integration is optional and controlled by the `GOOGLE_SCRIPT_URL` environment variable. If not configured, no data is sent externally.

---

## 8. Your Rights

You have the right to:

- **Access your data** — export all your data via `Settings → Export My Data`
- **Delete your account** — permanently erase all your data via `Settings → Delete Account`
- **Correct your data** — update your name and status at any time in Settings
- **Withdraw consent** — delete your account at any time; deletion is immediate and irreversible

Account deletion removes: your profile, all your contacts, all messages you sent or received, all call logs, and any key backups.

---

## 9. Children's Privacy

Synora is not directed at children under the age of 13. We do not knowingly collect personal information from children under 13. If you believe a child has provided us with personal information, please contact us and we will delete it.

---

## 10. Changes to This Policy

We may update this Privacy Policy from time to time. We will notify users of material changes by updating the "Effective Date" above. Continued use of Synora after changes constitutes acceptance of the updated policy.

---

## 11. Contact

For privacy questions, data requests, or concerns:

**Email:** yshubhranshu746@gmail.com  
**Developer:** Shubhranshu

---

*This privacy policy was written for Synora v2.1.0*