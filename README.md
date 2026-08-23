<div align="center">
  <img src="frontend/public/logo.png" alt="capki logo" width="88" />

  # capki

  **A small self-hosted web app for running your own internal Certificate Authority.**

  ![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)
  ![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi&logoColor=white)
  ![React](https://img.shields.io/badge/frontend-React-61DAFB?logo=react&logoColor=black)
  ![SQLite](https://img.shields.io/badge/storage-SQLite-003B57?logo=sqlite&logoColor=white)
  ![Docker](https://img.shields.io/badge/deploy-Docker%20%7C%20Podman-2496ED?logo=docker&logoColor=white)
</div>

capki issues TLS certs for internal services, mTLS client certs, VPN/S-MIME certs, or code-signing certs
— without paying a public CA or re-running the same `openssl` commands by hand every time someone needs
a cert.

### Contents

- [Why you might want this](#why-you-might-want-this)
- [What it does](#what-it-does)
- [Running with Docker (production)](#running-with-docker-production)
- [First run](#first-run)
- [Operations runbook](#operations-runbook)
- [Local development (no Docker)](#local-development-no-docker)
- [Database migrations](#database-migrations)

---

## Why you might want this

If you run any internal infrastructure — internal sites, service-to-service TLS, VPN clients, Kubernetes
ingress, and so on — you eventually need your own CA. The usual options are a folder of `openssl` scripts
someone wrote once (works, but no audit trail, no access control, and gets scary to touch a year later),
or a full enterprise PKI product that's more than a homelab or small team needs. capki sits in between: a
proper root + intermediate CA hierarchy, managed through a web UI, with just enough process — roles, an
approval flow, an audit log — to be trustworthy, without the operational weight of a "real" PKI platform.

## What it does

- 🏛️ **Runs its own CA hierarchy.** Generates a root CA (kept locked/offline by default) and an
  intermediate CA that does the day-to-day signing — a standard two-tier setup, not one self-signed cert
  doing everything.
- 📜 **Issues certificates from a CSR** — paste one in, or generate it right in the browser if you don't
  have `openssl` handy. Ships with a few built-in profiles (TLS server, mTLS client, user/S-MIME, code
  signing), each with its own allowed extensions and a maximum validity period.
- 🔄 **Renews and revokes certificates**, and regenerates the CRL (certificate revocation list)
  automatically whenever something is revoked.
- ✅ **Request/approval workflow**: a lower-privileged user can submit a CSR and wait for an operator or
  admin to approve it, instead of everyone having free rein to mint certificates.
- 🔔 **Expiry notifications**: certificates nearing expiry email and/or Telegram whoever originally
  requested them, so renewals don't get missed.
- 🔐 **Role-based access control** with four fixed roles (admin, operator, auditor, requester), so
  read-only auditors, day-to-day operators, and admins with root-CA access stay clearly separated.
- 🪪 **Two ways to log in**: local username/password, or SAML SSO against Microsoft Entra ID, so it can
  plug into an existing company identity provider instead of being one more separate account to manage.
- 🤖 **A REST API with token auth**, so scripts, CI/CD, or infrastructure-as-code can request certificates
  automatically instead of a human clicking through the UI every time.
- 📋 **An audit log** of who did what — issued, revoked, approved a request, changed a setting, and so on.
- 🌐 **Manages its own TLS certificate**, too — starts with a self-signed one on first boot, and you can
  later replace it with one signed by your own intermediate CA, or upload your own.

It runs as a single container backed by SQLite — no external database or extra services to stand up.

---

## Running with Docker (production)

```sh
docker compose up --build
```

Serves HTTPS on port 443 with a self-signed certificate generated on first boot. Replace it later from
Settings once logged in. All state (SQLite DB + wrapped key material) lives in the `capki-data` volume —
back that up.

Environment variables (see `docker-compose.yml` / `backend/src/capki/config.py`):

| Variable | Purpose |
|---|---|
| `APP_HOSTNAME` | Hostname used in the self-signed cert's CN/SAN |
| `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` | Bootstraps the first Admin user on first boot |
| `CA_MASTER_KEY_FILE` / `CA_MASTER_KEY` | KEK for the intermediate CA key + web TLS key (auto-generated into the volume if unset) |

> [!NOTE]
> The root CA passphrase and SAML IdP settings are intentionally **not** environment variables — enter
> them through the UI after first boot.

## First run

1. Log in as `INITIAL_ADMIN_USERNAME`.
2. **Certificate Authorities** tab -> Initialize Root CA (choose a strong passphrase — write it down
   somewhere durable; see [If you lose the root passphrase](#operations-runbook) below).
3. Initialize Intermediate CA (requires the root to be unlocked, which it is immediately after you just
   generated it). This is the CA that actually signs everything day to day.
4. **API Tokens** tab -> create a token for any automation that needs to call `POST /api/v1/certificates`
   with `Authorization: Bearer <token>`. Full endpoint reference: `/docs` (Swagger UI, auto-generated by
   FastAPI — also `/redoc` for a read-only alternative view, and `/openapi.json` for the raw spec).
5. Optional: **Settings** tab -> configure SAML (Entra ID), replace the self-signed web TLS cert,
   set up email/Telegram expiry notifications (a daily job emails and/or Telegrams whoever requested a
   certificate once it's within the configured warning window, default 30 days — set a user's Telegram
   Chat ID from the **Users** tab), and/or forward application + audit logs (JSON, UTC timestamps,
   audit entries include the requester's IP) to a Splunk/Cribl HTTP Event Collector and/or syslog.

## Operations runbook

> [!IMPORTANT]
> **Backups**: everything lives in the `capki-data` Docker volume (the SQLite DB plus, if auto-generated,
> the master key file). Back up the whole volume as one unit — a DB snapshot without the master key (or
> vice versa) is useless, since the intermediate CA key and web TLS key are encrypted with it.

> [!CAUTION]
> **If you lose the root passphrase**: the root CA becomes permanently unusable (there's no recovery —
> that's the point of it being passphrase-protected). Already-issued leaf certs and the existing
> intermediate stay valid and functional until they expire; you just can't renew the intermediate or sign
> a new one once the current one expires. Recovery is generating a brand-new root + intermediate and
> reissuing going forward.

> [!CAUTION]
> **If you lose the master key file** (`CA_MASTER_KEY_FILE`): the intermediate CA key and the web
> listener's TLS key both become unrecoverable — same situation as the root passphrase above for the
> intermediate side. It does **not** self-heal: `capki.bootstrap` (the pre-flight step in
> `entrypoint.sh`) will fail to decrypt the existing `tls_listener_config` row and crash before Uvicorn
> even starts, so the container won't come back up. Recovery: connect to the SQLite DB directly and
> delete the `tls_listener_config` row (id=1) — that forces a fresh self-signed cert on the next boot —
> then reissue/re-upload a real one from Settings once it's back up. If you supplied the master key
> yourself rather than letting it auto-generate, rotating it requires manually re-wrapping every
> `private_key_encrypted` blob in the DB; there's no built-in rotation tool in v1.

> [!NOTE]
> **Root auto-relock**: unlocking the root (`POST /ca/root/unlock`) only lasts
> `ROOT_CA_AUTO_RELOCK_MINUTES` (default 30) or until the process restarts, whichever comes first — this
> is intentional, not a bug.

**RBAC roles** (fixed in v1, not editable via UI):

| Role | Access |
|---|---|
| `admin` | Full access: users, CAs, settings, root CA unlock/lock |
| `operator` | Day-to-day certificate issuance, revocation, and approving requests |
| `auditor` | Read-only access to certificates, CAs, settings, and the audit log |
| `requester` | Can submit certificate requests and retrieve their own issued certificates |

**Cert profiles** (fixed in v1) — each has a `max_validity_days` cap enforced at issuance:

| Profile | Purpose |
|---|---|
| `server` | TLS server (serverAuth + clientAuth) |
| `client` | mTLS client (clientAuth) |
| `user` | S/MIME — requires an email SAN |
| `code_signing` | Code signing |

## Local development (no Docker)

Backend:

```sh
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
export PYTHONPATH=src DATABASE_PATH=/tmp/capki_dev.db CA_MASTER_KEY_FILE=/tmp/capki_master.key \
       TLS_MATERIALIZED_DIR=/tmp/capki_tls APP_HOSTNAME=localhost
alembic upgrade head
python -m capki.bootstrap   # generates the self-signed TLS cert once
uvicorn capki.main:app --reload --host 127.0.0.1 --port 8443 \
    --ssl-certfile /tmp/capki_tls/tls.crt --ssl-keyfile /tmp/capki_tls/tls.key
```

Frontend (proxies `/api` to the backend above, see `vite.config.ts`):

```sh
cd frontend
npm install
npm run dev
```

For a production-shaped build, `npm run build` outputs straight into `backend/src/capki/static/`, which
`main.py` serves directly — no separate frontend server needed.

## Database migrations

After changing a model under `backend/src/capki/db/models/`:

```sh
cd backend && . .venv/bin/activate
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```
