# CloudFen v14 — Security Layer 2 Guide

## What was added in v14

### 1. Hardened `.htaccess` files (every directory)

| File | What it does |
|------|-------------|
| `cloudfen_out/.htaccess` | Blocks SQL injection in query strings, null-byte attacks, common exploit scanner paths, dangerous file extensions (`.bak`, `.sql`, `.env`, etc.), limits HTTP methods to GET/POST/HEAD, adds HSTS + COOP + CORP headers, hides Server/PHP version |
| `admin/.htaccess` | Blocks empty User-Agent scanners |
| `admin/super/.htaccess` | Same, for super-admin area |
| `api/.htaccess` | Adds no-cache headers, blocks scanners |
| `auth/.htaccess` | No-cache headers prevent login page caching |
| `employee/.htaccess` | No directory indexing, method restriction |
| `includes/.htaccess` | **Full deny** — PHP helpers can never be hit by URL |
| `vendor/.htaccess` | **Full deny** — Composer packages never served directly |
| `assets/.htaccess` | PHP execution blocked inside static assets folder |

---

### 2. Session hijack detection (`includes/security.php`)

Every authenticated session is now bound to a fingerprint of:
- The client's User-Agent (first 200 characters)
- The first two IP octets (tolerates mobile LTE churn)

If a stolen cookie is used from a different browser or network, the fingerprint mismatches and the session is immediately invalidated. The user is redirected to `login.php?security=1`.

**Tuning:** The fingerprint is HMAC-keyed with `JWT_SECRET`, so rotating that secret invalidates all sessions.

---

### 3. CSRF token rotation

`verifyCsrfToken(true)` now rotates the CSRF token after every successful form submission, so old tokens cannot be replayed. This is applied to all 13 POST handlers.

---

### 4. Honeypot field on auth forms

`honeypotField()` outputs a hidden `<input name="cf_url">` that is invisible to humans but filled by bots. `checkHoneypot()` silently terminates bot submissions before they touch the database.

Added to: `login.php`, `forgot.php`, `reset.php`.

---

### 5. Request size guard

`guardRequestSize(MAX_POST_BYTES)` (default 5 MB) aborts oversized POST bodies before PHP processes them — protects against memory-exhaustion DoS. Added to all 10 POST-receiving pages.

---

### 6. Security headers (expanded)

New headers added to every PHP response:
- `Strict-Transport-Security` — forces HTTPS for 1 year
- `Cross-Origin-Opener-Policy: same-origin` — prevents Spectre-style cross-origin leaks
- `Cross-Origin-Resource-Policy: same-origin` — prevents other origins embedding our responses
- `X-XSS-Protection: 1; mode=block` — legacy browser XSS filter
- `Permissions-Policy` — camera, mic, geolocation, payment, USB all blocked

---

### 7. No-cache headers on auth pages

`sendNoCacheHeaders()` prevents browsers from caching login/reset/password pages, which could otherwise expose them via browser back-button after logout.

---

### 8. Trusted-proxy IP resolution

`getClientIpSecure()` validates the `X-Forwarded-For` header only when `REMOTE_ADDR` is a trusted proxy. This prevents IP spoofing via forged headers on non-proxy requests.

Configure your proxy IPs in `cf_config/configT.php`:
```php
define('TRUSTED_PROXIES', ['127.0.0.1', '::1', 'your.load.balancer.ip']);
```

Session cookie HTTPS detection uses `HTTPS` from the web server directly. It accepts `X-Forwarded-Proto`, `X-Forwarded-SSL`, and `CF-Visitor` only when `REMOTE_ADDR` is in this trusted proxy list. Do not add addresses that users can connect from directly.

---

### 9. Last-login audit trail

Successful logins now write `last_login_at` and `last_login_ip` to the `users` table. Admins can use this to detect account sharing or suspicious access patterns.

---

### 10. Download failure logging

`serve_document.php` now logs every failed download attempt to the `download_failures` table with reason codes: `invalid_params`, `token_expired`, `invalid_token`, `not_found`, `access_denied`, `path_invalid`, `integrity_fail`.

---

## 3-step deployment checklist

### Step 1 — Database migration
Run `config/migration_v14_security.sql` in phpMyAdmin once.
(Safe to re-run — uses `IF NOT EXISTS` and `INSERT IGNORE`.)

### Step 2 — Upload files
Replace `cloudfen_out/` as normal. Drop `.htaccess` files into each subdirectory. Upload `cf_config/configT.php`.

### Step 3 — Configure trusted proxies (if applicable)
Edit `TRUSTED_PROXIES` in `cf_config/configT.php` if you use a load balancer or Cloudflare.

---

## Layer summary

| Layer | Mechanism | Location |
|-------|-----------|----------|
| 1 | cf_uploads outside public_html | cPanel file system |
| 2a | Directory deny + no-exec | `.htaccess` files |
| 2b | Session fingerprint binding | `security.php` |
| 2c | HMAC signed download tokens | `serve_document.php` |
| 2d | SHA-256 file integrity check | `serve_document.php` |
| 2e | CSRF token rotation | All POST handlers |
| 2f | Honeypot on auth forms | `auth/*.php` |
| 2g | Request size guard | All POST handlers |
| 2h | Trusted-proxy IP resolution | `security.php` |
| 2i | Download failure logging | `serve_document.php` |
| 2j | No-cache on auth pages | `auth/*.php` |
| 2k | Hardened security headers | `security.php` + `.htaccess` |
