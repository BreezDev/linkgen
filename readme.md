# The Plugin Plug — One-Time Link Delivery

This repository contains a Flask application for delivering plugin ZIPs through one-time download links. Admins can upload files, generate tokens in bulk, and track usage while customers receive a branded download page.

## Features
- Admin-only dashboard secured with a password (set via `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`).
- Upload ZIP files to local storage.
- Bundle multiple files into a single one-time link (downloads stream as a ZIP when more than one file is attached).
- Generate one-time download links with optional expirations, customer emails, and order prefixes.
- Track link status, usage metadata, and revoke access when needed.
- Branded public download page with one-time enforcement.

## Getting started
1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Set environment variables (recommended):
   ```bash
   export FLASK_APP=app.py
   export FLASK_SECRET="change-me"
   export MAX_UPLOAD_MB=500  # optional: cap uploads at this size (MB)
   export ADMIN_PASSWORD="choose-a-strong-password"
   # or supply ADMIN_PASSWORD_HASH instead of ADMIN_PASSWORD
   ```

3. Initialize the database and run the server:
   ```bash
   flask --app app.py init-db
   flask --app app.py run
   ```

4. Visit `/admin/login` to sign in. Use the configured admin password. Upload files and generate links from the dashboard.

## Notes for PythonAnywhere
- The app stores uploads in the local `storage/` directory by default. Point this to external object storage if you outgrow local disk.
- Use HTTPS for customer-facing downloads. Configure your domain and TLS in PythonAnywhere.
- Consider adding a daily scheduled task to flag expired links and rotate backups of the `linkgen.db` SQLite database.

## Security and safety considerations
- Tokens are never stored in plain text; only SHA-256 hashes are persisted.
- One-time downloads mark links as used immediately before serving files to reduce race conditions.
- Admin routes are protected with session auth; rate limiting and IP allow-listing can be layered via your deployment environment.
- All uploaded ZIPs should be scanned for malware before becoming downloadable. Pair your deployment with a scheduled ClamAV (or
  equivalent) scan of the `storage/` directory, quarantine anything suspicious, and keep virus definitions updated. The download page
  messaging makes it clear that files are scanned so customers know the content is clean.
- Serve downloads over HTTPS only, set `Secure`/`HttpOnly` on cookies, and rotate `FLASK_SECRET` regularly. If you host behind a
  CDN or WAF, enable basic rate limiting to deter brute-force token guessing.
- Keep the operating system patched, rotate your admin password, and back up `linkgen.db` + file storage in a secure location.

## Handling large uploads and 413 errors
- The app caps uploads using Flask's `MAX_CONTENT_LENGTH` (configured via `MAX_UPLOAD_MB`, default `500`). If you see "413 Request Entity Too Large" inside Flask, increase `MAX_UPLOAD_MB` in your environment.
- When running behind Nginx or another reverse proxy, also raise the upstream body size limit (e.g., `client_max_body_size 500M;` in your Nginx site config) so the proxy forwards larger files to Flask.
- After changing the limit, restart both the proxy and the Flask process to ensure the new values are active.

## Customer accounts and Antistock order statuses
You can keep customer metadata in sync with Antistock to enrich the admin dashboard and to double-check that only paid orders get
links.

1. Generate an API token in Antistock and expose it to the app as `ANTISTOCK_API_TOKEN`.
2. Use the [Antistock Customers endpoint](https://developers.antistock.io/api-reference#tag/customers) to pull the latest buyers
   and order states. For example, a `GET https://api.antistock.io/customers` call (authorized with your token) returns customers
   and their current order statuses.
3. Cross-reference the `customer_email` and `order_id` fields you store on `DownloadLink` records with the Antistock payload before
   generating new tokens. That lets you block revoked or refunded orders and quickly look up support issues.
4. Consider a daily sync job that caches customer accounts (email, order status, last purchase date) in a local table so you can
   search by status in the admin UI without hitting the Antistock API for every request.
5. When sending download links, note the verified order status (e.g., `paid`, `fulfilled`, `refunded`) alongside the link so
   customers understand whether replacements require a fresh purchase. This also gives you an audit trail tying each one-time token
   to the originating Antistock order.
