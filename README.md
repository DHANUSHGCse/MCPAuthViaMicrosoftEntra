# 🔐 MCP Entra Proxy

> Connect **Claude.ai remote MCP servers** to your private network using **Microsoft Entra ID (Azure AD)** OAuth 2.0 — with support for multiple MCP servers each backed by their own Entra application.

📖 **Full illustrated guide:** open [`mcp-oauth-blog.html`](./mcp-oauth-blog.html) in your browser — covers the OAuth 2.0 primer, Claude's discovery fallback chain, sequence diagrams, and all proxy logic explained step by step with reference links to every RFC.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MCP](https://img.shields.io/badge/MCP-1.3.0-6B46C1)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📖 Table of Contents

- [Background](#background)
- [Architecture](#architecture)
- [The Discovery Problem](#the-discovery-problem)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
  - [Section A — Single Global Auth](#section-a--single-global-auth)
  - [Section B — Per-Server Auth](#section-b--per-server-auth)
- [Microsoft Entra Setup](#microsoft-entra-setup)
- [Running in Production](#running-in-production)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Background

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) allows Claude.ai to call external tools over HTTP. When those tools live inside a **corporate private network** protected by **Microsoft Entra ID**, you need to broker the OAuth 2.0 flow between Claude and Entra.

This project implements a lightweight **Auth Proxy** in FastAPI that:

1. Serves the correct OAuth discovery metadata that Claude's connector expects
2. Rewrites parameters that conflict with Entra's validation rules (`resource`, `scope`, `redirect_uri`)
3. Orchestrates the full Authorization Code + PKCE flow transparently
4. Validates incoming JWTs on every MCP request

---

## Architecture

```
┌─────────────┐     OAuth discovery     ┌──────────────────┐     ┌─────────────────┐
│  Claude.ai  │ ──────────────────────► │   Auth Proxy      │ ──► │  MS Entra ID    │
│  MCP Client │ ◄────────────────────── │  (this project)   │ ◄── │  (login.ms.com) │
└─────────────┘     token / redirect    └──────────────────┘     └─────────────────┘
                                                │
                              Bearer JWT        │
                    ┌──────────────────────────┤
                    ▼                           ▼
          ┌─────────────────┐       ┌─────────────────────┐
          │  HR MCP Server  │       │ Compliance MCP Server│
          │ /FirstMCPServer │       │ /SecondMCPServer     │
          └─────────────────┘       └─────────────────────┘
```

---

## The Discovery Problem

Claude follows the **RFC 9728 Protected Resource Metadata** discovery chain when connecting to a remote MCP server:

| Step | URL Claude calls | What it expects |
|------|-----------------|-----------------|
| ① | `/.well-known/protected-resource/<ServerName>` | Resource-specific auth server pointer |
| ② | `/.well-known/protected-resource` | Global fallback |
| ③ | `/.well-known/oauth-authorization-server` | RFC 8414 AS metadata |
| ④ | `/authorize` | Legacy last resort (global only ⚠️) |

**Problem:** If step ① returns 404 (e.g. your server only had the un-suffixed path), Claude falls all the way to the global `/authorize`, losing any per-resource isolation. This breaks use-cases where different MCP servers need different Entra app registrations.

**Solution:** Serve step ① correctly — with a `resource` value matching the exact MCP server URL — and proxy `/authorize` and `/token` to rewrite conflicting parameters.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Two Microsoft Entra app registrations (one per MCP server, or one shared)
- A domain with HTTPS (e.g. `https://example.com`)

### 1. Clone & install

```bash
git clone https://github.com/your-org/mcp-entra-proxy.git
cd mcp-entra-proxy
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your Entra tenant/app details
```

### 3. Run (development)

```bash
uvicorn src.main:app --reload --port 8000
```

### 4. Run (production)

```bash
uvicorn src.main:app \
  --host 0.0.0.0 \
  --port 443 \
  --ssl-keyfile /etc/ssl/private/key.pem \
  --ssl-certfile /etc/ssl/certs/cert.pem \
  --workers 4
```

### 5. Add to Claude

In Claude.ai → Settings → Integrations → Add MCP Server:

```
https://example.com/FirstMCPServer
https://example.com/SecondMCPServer
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# ── Microsoft Entra ────────────────────────────────────────────
TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# HR MCP Server — Entra App Registration
HR_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
HR_CLIENT_SECRET=your-hr-client-secret
HR_SCOPE=api://hr-app-client-id/read

# Compliance MCP Server — Entra App Registration
COMPLIANCE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
COMPLIANCE_CLIENT_SECRET=your-compliance-client-secret
COMPLIANCE_SCOPE=api://compliance-app-client-id/read

# ── Server ─────────────────────────────────────────────────────
BASE_URL=https://example.com
```

| Variable | Description |
|----------|-------------|
| `TENANT_ID` | Your Azure AD tenant ID |
| `HR_CLIENT_ID` | Client ID of the HR Entra app registration |
| `HR_CLIENT_SECRET` | Client secret for the HR app |
| `HR_SCOPE` | OAuth scope exposed by the HR app (`api://<app-id>/<scope-name>`) |
| `COMPLIANCE_*` | Same for the Compliance app |
| `BASE_URL` | Public HTTPS base URL of this proxy server |

---

## Project Structure

```
mcp-entra-proxy/
├── src/
│   ├── main.py           # FastAPI app — proxy + MCP servers
│   ├── auth.py           # JWT validation helpers
│   └── config.py         # Settings loaded from .env
├── docs/
│   └── blog.html         # Full technical blog post (self-contained)
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions — lint + test
├── .env.example          # Environment variable template
├── requirements.txt      # Python dependencies
├── Dockerfile            # Container build
├── docker-compose.yml    # Local dev with Docker
└── README.md
```

---

## How It Works

### Section A — Single Global Auth

If all your MCP servers share one Entra app, simply expose the OAuth AS Metadata at the well-known URL and Claude's fallback mechanism will find it automatically.

Serve at `GET /.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize",
  "token_endpoint": "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token",
  "scopes_supported": ["api://<app-id>/<scope>"],
  "jwks_uri": "https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys",
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"]
}
```

Your MCP endpoints must return `HTTP 401 WWW-Authenticate: Bearer` for unauthenticated requests.

---

### Section B — Per-Server Auth

For isolated authorization per MCP server:

#### Step 1 — Resource metadata (served by this proxy)

`GET /.well-known/protected-resource/FirstMCPServer` → returns:

```json
{
  "resource": "https://example.com/FirstMCPServer",
  "authorization_servers": ["https://example.com/FirstAuth"],
  "scopes_supported": ["api://hr-app-id/read"],
  "bearer_methods_supported": ["header"]
}
```

#### Step 2 — AS metadata (served by this proxy)

`GET /.well-known/oauth-authorization-server/FirstAuth` → returns proxy endpoints:

```json
{
  "issuer": "https://example.com/FirstAuth",
  "authorization_endpoint": "https://example.com/FirstAuth/authorize",
  "token_endpoint": "https://example.com/FirstAuth/token",
  ...
}
```

#### Step 3 — /authorize proxy logic

| Action | Reason |
|--------|--------|
| Strip `resource` param | Entra validates resource against app registration URI — mismatch = error |
| Rewrite `redirect_uri` → proxy callback | Must match Entra-registered URI |
| Encode original Claude callback in `state` | Replay after Entra redirects back |

#### Step 4 — /oauth/callback

Decode `state` → extract Claude's original `redirect_uri` → re-add `resource` → redirect to `claude.ai/api/mcp/auth/callback`.

#### Step 5 — /token proxy logic

| Action | Reason |
|--------|--------|
| Strip `scope` | Sending both resource + scope to Entra token endpoint can cause validation failure |
| Rewrite `redirect_uri` | Must exactly match what was sent in /authorize |

---

## Microsoft Entra Setup

For each MCP server, create an **App Registration** in Entra:

1. **Azure Portal** → Azure Active Directory → App Registrations → New Registration
2. Set **Redirect URI** (Web):
   - HR app: `https://example.com/FirstAuth/oauth/callback`
   - Compliance app: `https://example.com/SecondAuth/oauth/callback`
3. **Expose an API**:
   - Set App ID URI: `api://<client-id>`
   - Add a scope (e.g. `read`) — make sure to note the full scope string
4. **Certificates & Secrets** → New client secret → copy the value into `.env`
5. **Authentication** → Enable **Access tokens** under Implicit grant (if needed for your setup)
6. **Token configuration** → Add optional claims if you need `upn`, `groups`, etc.

> ⚠️ The `redirect_uri` registered in Entra must **exactly match** what the proxy sends in `/authorize` and `/token` requests.

---

## Running in Production

### Docker

```bash
docker build -t mcp-entra-proxy .
docker run -d \
  --env-file .env \
  -p 443:443 \
  -v /etc/ssl:/etc/ssl:ro \
  mcp-entra-proxy
```

### Docker Compose (local dev)

```bash
docker-compose up --build
```

### Systemd service

```ini
[Unit]
Description=MCP Entra Proxy
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/mcp-entra-proxy
EnvironmentFile=/opt/mcp-entra-proxy/.env
ExecStart=/opt/mcp-entra-proxy/.venv/bin/uvicorn src.main:app \
    --host 0.0.0.0 --port 443 \
    --ssl-keyfile /etc/ssl/private/key.pem \
    --ssl-certfile /etc/ssl/certs/cert.pem \
    --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/protected-resource/{server}` | Resource-specific OAuth metadata (RFC 9728) |
| `GET` | `/.well-known/oauth-authorization-server/{auth}` | AS metadata (RFC 8414) |
| `GET` | `/{auth}/authorize` | Proxy → strips resource, rewrites redirect → Entra |
| `GET` | `/{auth}/oauth/callback` | Entra callback → decode state → forward to Claude |
| `POST` | `/{auth}/token` | Proxy → strips scope, fixes redirect → Entra token |
| `*` | `/FirstMCPServer` | HR MCP Server (JWT-protected) |
| `*` | `/SecondMCPServer` | Compliance MCP Server (JWT-protected) |

---

## Contributing

Pull requests are welcome! Please open an issue first to discuss larger changes.

```bash
# Run tests
pytest tests/ -v

# Lint
ruff check src/
```

---

## License

[MIT](LICENSE) © Your Organisation
