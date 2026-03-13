import os
import json
import urllib.parse
import base64
from dotenv import load_dotenv
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from jose import jwt, JWTError
import uvicorn
from mcp.server.fastmcp import FastMCP

load_dotenv()

# ── Environment ──────────────────────────────────────────────────────────────
TENANT_ID            = os.environ["TENANT_ID"]
BASE_URL             = os.environ["BASE_URL"]           # e.g. https://example.com
CLAUDE_CALLBACK_BASE = os.environ["CLAUDE_CALLBACK_BASE"]

# Microsoft Entra endpoints
ENTRA_AUTH      = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
ENTRA_TOKEN     = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

# Microsoft publishes signing keys at a well-known, stable URL per tenant.
# Map directly — no need for a dynamic JWKS URI lookup.
ENTRA_JWKS_URL  = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

# Cache: loaded once at startup, refreshed only on key-not-found (kid mismatch)
_jwks_cache: dict | None = None

# ── App config per MCP server ─────────────────────────────────────────────────
APPS = {
    "FirstAuth": {
        "client_id":     os.environ["HR_CLIENT_ID"],
        "client_secret": os.environ["HR_CLIENT_SECRET"],
        "scope":         os.environ["HR_SCOPE"],
        "resource":      f"{BASE_URL}/FirstMCPServer",
    },
    "SecondAuth": {
        "client_id":     os.environ["COMPLIANCE_CLIENT_ID"],
        "client_secret": os.environ["COMPLIANCE_CLIENT_SECRET"],
        "scope":         os.environ["COMPLIANCE_SCOPE"],
        "resource":      f"{BASE_URL}/SecondMCPServer",
    },
}

app = FastAPI(title="MCP Auth Proxy")


# ── JWKS cache helpers ────────────────────────────────────────────────────────

async def get_microsoft_keys(force_refresh: bool = False) -> dict:
    """Return Microsoft's public signing keys, using a simple in-process cache.

    Microsoft rotates keys periodically. We load once at startup and force a
    single refresh when we encounter a kid that isn't in the cache, which
    handles key rollover automatically without any scheduled jobs.
    """
    global _jwks_cache
    if _jwks_cache is None or force_refresh:
        async with httpx.AsyncClient() as c:
            resp = await c.get(ENTRA_JWKS_URL, timeout=5)
            resp.raise_for_status()
            _jwks_cache = resp.json()
    return _jwks_cache


# ── Token validation ──────────────────────────────────────────────────────────

async def verify_token(request: Request) -> dict:
    """Validate the incoming Bearer token against Microsoft's signing keys."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
            detail="Missing bearer token",
        )
    token = auth[7:]

    # Extract the key ID from the token header so we can pick the right key
    header = jwt.get_unverified_header(token)
    kid    = header.get("kid")

    # Try cached keys first; if kid is missing, force a refresh once
    jwks = await get_microsoft_keys()
    known_kids = {k["kid"] for k in jwks.get("keys", [])}
    if kid not in known_kids:
        jwks = await get_microsoft_keys(force_refresh=True)

    try:
        # python-jose accepts a JWKS dict directly — it selects the key by kid
        claims = jwt.decode(
            token, jwks,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return claims
    except JWTError as e:
        raise HTTPException(status_code=401, detail=str(e))


# =============================================================================
# DISCOVERY ENDPOINTS
# =============================================================================

@app.get("/.well-known/protected-resource/{server_name}")
async def protected_resource_metadata(server_name: str):
    """Resource-specific protected resource metadata (RFC 9728).

    Claude checks this URL first to find which authorization server
    is responsible for a given MCP server.
    """
    auth_map = {
        "FirstMCPServer":  "FirstAuth",
        "SecondMCPServer": "SecondAuth",
    }
    auth_name = auth_map.get(server_name)
    if not auth_name:
        raise HTTPException(status_code=404)
    cfg = APPS[auth_name]
    return JSONResponse({
        "resource":              cfg["resource"],
        "authorization_servers": [f"{BASE_URL}/{auth_name}"],
        "scopes_supported":      [cfg["scope"]],
        "bearer_methods_supported": ["header"],
    })


@app.get("/.well-known/oauth-authorization-server/{auth_name}")
async def as_metadata(auth_name: str):
    """Authorization Server Metadata (RFC 8414).

    Points Claude at our proxy's /authorize and /token endpoints,
    with jwks_uri mapped directly to Microsoft's discovery keys URL.
    """
    if auth_name not in APPS:
        raise HTTPException(status_code=404)
    cfg  = APPS[auth_name]
    base = f"{BASE_URL}/{auth_name}"
    return JSONResponse({
        "issuer":                base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint":        f"{base}/token",
        "scopes_supported":      [cfg["scope"]],
        "jwks_uri":              ENTRA_JWKS_URL,   # direct map to Microsoft keys
        "response_types_supported":          ["code"],
        "grant_types_supported":             ["authorization_code"],
        "code_challenge_methods_supported":  ["S256"],
    })


# =============================================================================
# /authorize  — strip resource, rewrite redirect_uri, forward to Entra
# =============================================================================

@app.get("/{auth_name}/authorize")
async def proxy_authorize(auth_name: str, request: Request):
    """Proxy /authorize to Microsoft Entra.

    Key transformations:
    1. Strip `resource` — Entra validates it against the app registration URI
       and rejects our MCP server URL.
    2. Stash Claude's original redirect_uri + state in our own state param.
    3. Rewrite redirect_uri to our callback (must be registered in Entra app).
    """
    if auth_name not in APPS:
        raise HTTPException(status_code=404)
    cfg = APPS[auth_name]

    params = dict(request.query_params)

    # ① Stash Claude's original redirect_uri + state
    original_state = {
        "claude_redirect_uri": params.pop("redirect_uri", ""),
        "claude_state":        params.get("state", ""),
    }
    encoded_state = base64.urlsafe_b64encode(
        json.dumps(original_state).encode()
    ).decode()

    # ② Strip resource — Entra rejects our MCP server URL as a resource value
    params.pop("resource", None)

    # ③ Inject our callback + packed state
    params["redirect_uri"] = f"{BASE_URL}/{auth_name}/oauth/callback"
    params["state"]        = encoded_state
    params["client_id"]    = cfg["client_id"]

    entra_url = ENTRA_AUTH + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(entra_url, status_code=302)


# =============================================================================
# /oauth/callback  — Microsoft redirects here; re-attach resource, forward to Claude
# =============================================================================

@app.get("/{auth_name}/oauth/callback")
async def oauth_callback(auth_name: str, request: Request):
    """Receive auth code from Microsoft and forward it to Claude.

    Re-adds the resource parameter that we stripped in /authorize,
    then redirects to Claude's original callback URI.
    """
    if auth_name not in APPS:
        raise HTTPException(status_code=404)
    cfg = APPS[auth_name]

    params = dict(request.query_params)
    code   = params.get("code")
    state  = params.get("state", "")

    # Decode the stashed state
    try:
        original = json.loads(base64.urlsafe_b64decode(state + "=="))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    claude_redirect = original["claude_redirect_uri"]
    claude_state    = original["claude_state"]

    # Forward to Claude — re-add resource so Claude can match the token
    callback_params = {
        "code":     code,
        "state":    claude_state,
        "resource": cfg["resource"],
    }
    final_url = claude_redirect + "?" + urllib.parse.urlencode(callback_params)
    return RedirectResponse(final_url, status_code=302)


# =============================================================================
# /token  — strip scope, fix redirect_uri, forward to Entra
# =============================================================================

@app.post("/{auth_name}/token")
async def proxy_token(auth_name: str, request: Request):
    """Proxy /token to Microsoft Entra.

    Key transformations:
    1. Strip `scope` — when both resource and scope are present Entra can
       reject the request; omitting scope lets Entra apply the app manifest defaults.
    2. Rewrite redirect_uri to match exactly what was sent in /authorize.
    3. Inject client credentials.
    """
    if auth_name not in APPS:
        raise HTTPException(status_code=404)
    cfg = APPS[auth_name]

    body = dict(await request.form())

    # ① Strip scope to avoid Entra resource/scope conflict
    body.pop("scope", None)

    # ② Must match the redirect_uri used in /authorize exactly
    body["redirect_uri"]  = f"{BASE_URL}/{auth_name}/oauth/callback"
    body["client_id"]     = cfg["client_id"]
    body["client_secret"] = cfg["client_secret"]

    async with httpx.AsyncClient() as c:
        resp = await c.post(ENTRA_TOKEN, data=body)

    return JSONResponse(resp.json(), status_code=resp.status_code)


# =============================================================================
# MCP SERVERS — each protected with JWT validation
# =============================================================================

# ── HR MCP Server ─────────────────────────────────────────────────────────────
hr_mcp = FastMCP("HR MCP Server")


@hr_mcp.tool()
async def get_employee(employee_id: str) -> dict:
    """Return employee details from the HR system."""
    # Replace with your real HR data source call
    return {"id": employee_id, "name": "Jane Smith", "department": "Engineering"}


@app.api_route("/FirstMCPServer", methods=["GET", "POST"])
async def hr_mcp_endpoint(request: Request):
    # Guard: returns 401 for unauthenticated requests (triggers Claude OAuth flow)
    await verify_token(request)
    hr_asgi = hr_mcp.get_asgi_app()
    return await hr_asgi(request.scope, request.receive, request._send)


# ── Compliance MCP Server ─────────────────────────────────────────────────────
compliance_mcp = FastMCP("Compliance MCP Server")


@compliance_mcp.tool()
async def get_policy(policy_id: str) -> dict:
    """Return compliance policy details."""
    # Replace with your real compliance data source call
    return {"id": policy_id, "title": "Data Retention", "status": "active"}


@app.api_route("/SecondMCPServer", methods=["GET", "POST"])
async def compliance_mcp_endpoint(request: Request):
    await verify_token(request)
    compliance_asgi = compliance_mcp.get_asgi_app()
    return await compliance_asgi(request.scope, request.receive, request._send)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=4,
        # Production: add ssl_keyfile + ssl_certfile
    )
