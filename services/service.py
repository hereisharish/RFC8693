#!/usr/bin/env python3
"""Generic demo microservice (stdlib only). Run N copies to form a chain.

For each request it:
  1. validates the bearer token via Keycloak introspection (must be active and addressed to this service)
  2. reports who the *user* is (sub) and who is calling on their behalf (the nested "act" chain)
  3. if NEXT_SERVICE_URL is set: performs an RFC 8693 delegation token exchange
       subject_token = the token it received, actor_token = its own client-credentials token,
       scope = delegate-to:<next client>
     and calls the next service with the new token.

Env: SERVICE_NAME, CLIENT_SECRET, PORT, KC_URL, REALM, NEXT_SERVICE_URL, NEXT_CLIENT_ID
"""
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ["SERVICE_NAME"]
SECRET = os.environ.get("CLIENT_SECRET", f"{NAME}-secret")
PORT = int(os.environ.get("PORT", "8081"))
KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("REALM", "rfc8693")
NEXT_URL = os.environ.get("NEXT_SERVICE_URL")
NEXT_CLIENT = os.environ.get("NEXT_CLIENT_ID")
TITLE = os.environ.get("SERVICE_TITLE", NAME)       # business label shown in the UI
DATA = os.environ.get("SERVICE_DATA")               # JSON payload this service owns (the last hop's answer)
# The only actor allowed to call this service on a user's behalf, i.e. the approved predecessor in the
# chain. Unset means "no restriction" (service-1 is called by the user directly, so it stays unset).
ALLOWED_CALLER = os.environ.get("ALLOWED_CALLER")

AUDIT = deque(maxlen=200)  # what this service actually saw; served at GET /audit

OIDC = f"{KC_URL}/realms/{REALM}/protocol/openid-connect"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class HttpError(Exception):
    def __init__(self, status, body):
        super().__init__(f"{status}: {body}")
        self.status, self.body = status, body


def post_form(url, form):
    req = urllib.request.Request(url, urllib.parse.urlencode(form).encode(),
                                 {"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, e.read().decode())


def introspect(token):
    return post_form(f"{OIDC}/token/introspect",
                     {"token": token, "client_id": NAME, "client_secret": SECRET})


def own_token():
    """The actor_token: proves *this* service is the one acting."""
    return post_form(f"{OIDC}/token", {"grant_type": "client_credentials",
                                       "client_id": NAME, "client_secret": SECRET})["access_token"]


def exchange(subject_token):
    return post_form(f"{OIDC}/token", {
        "grant_type": TOKEN_EXCHANGE, "client_id": NAME, "client_secret": SECRET,
        "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": own_token(), "actor_token_type": ACCESS_TOKEN_TYPE,
        "scope": f"delegate-to:{NEXT_CLIENT}",
    })["access_token"]


def actors(act):
    """Nested act -> list, most recent actor first."""
    out = []
    while isinstance(act, dict):
        out.append(act.get("client_id") or act.get("sub"))
        act = act.get("act")
    return out


def jwt_claims(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def record(decision, reason, user=None, sub=None, chain=None, token_id=None):
    """One audit line per request this service handled, allowed or refused."""
    entry = {
        # epoch millis so the consolidated report can render every source in one timezone; containers
        # run UTC while Keycloak's event log is read in local time.
        "ts": int(time.time() * 1000),
        "service": NAME, "title": TITLE,
        "decision": decision, "reason": reason,
        "user": user, "sub": sub,
        "called_by": (chain[0] if chain else user),
        "delegation_chain": list(reversed(chain)) if chain else [],
        "token_id": token_id,
    }
    AUDIT.append(entry)
    print(f"[{NAME}] AUDIT {decision.upper():6} {reason:34} user={user} "
          f"called_by={entry['called_by']} chain={'->'.join(entry['delegation_chain']) or '-'}", flush=True)
    return entry


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def cors(self):
        """The browser calls service-1 directly. Safe to allow any origin: these endpoints are
        bearer-authenticated and never read cookies, so there is no ambient authority to steal."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    def reply(self, status, body):
        data = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.cors()
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path.split("?")[0].rstrip("/") == "/audit":
            return self.reply(200, {"service": NAME, "title": TITLE,
                                    "approved_caller": ALLOWED_CALLER, "entries": list(AUDIT)})

        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            record("deny", "no bearer token")
            return self.reply(401, {"service": NAME, "error": "missing bearer token"})
        token = auth[7:]

        info = introspect(token)
        aud = info.get("aud") or []
        aud = [aud] if isinstance(aud, str) else aud
        user = info.get("preferred_username") or info.get("sub")
        chain = actors(info.get("act"))
        tid = info.get("jti")

        if not info.get("active"):
            # Introspection reports inactive when this client is not in the token's audience, so a
            # token addressed elsewhere lands here rather than in the audience check below.
            record("deny", "token not active for this service", token_id=tid)
            return self.reply(401, {"service": NAME, "error": "token not active"})
        if NAME not in aud:
            record("deny", f"audience {aud} excludes {NAME}", user, info.get("sub"), chain, tid)
            return self.reply(403, {"service": NAME, "error": f"token audience {aud} does not include {NAME}"})

        # The approved call graph: only the designated predecessor may delegate into this service.
        # Keycloak blocks disallowed hops at issuance; this refuses them at the door as well, so a
        # token minted before the rule existed, or by a future misconfiguration, still gets rejected.
        caller = chain[0] if chain else user
        if ALLOWED_CALLER and caller != ALLOWED_CALLER:
            record("deny", f"caller {caller} is not the approved {ALLOWED_CALLER}",
                   user, info.get("sub"), chain, tid)
            return self.reply(403, {
                "service": NAME,
                "error": f"{NAME} only accepts calls delegated by {ALLOWED_CALLER}, but this token was "
                         f"delegated by {caller}",
                "delegation_chain": list(reversed(chain)),
            })

        call_path = [user] + list(reversed(chain)) + [NAME]
        record("allow", "validated", user, info.get("sub"), chain, tid)

        result = {
            "service": NAME,
            "title": TITLE,
            "user": user,
            "sub": info.get("sub"),
            "immediate_caller": chain[0] if chain else user,
            "call_path": " -> ".join(call_path),
            "act": info.get("act"),
        }
        if DATA:
            result["data"] = json.loads(DATA)

        if NEXT_URL:
            try:
                new_token = exchange(token)
            except HttpError as e:
                result["token_exchange_error"] = json.loads(e.body) if e.body.startswith("{") else e.body
                return self.reply(502, result)
            c = jwt_claims(new_token)
            result["exchanged_token_for_next_hop"] = {k: c.get(k) for k in ("sub", "azp", "aud", "may_act", "act")}
            req = urllib.request.Request(NEXT_URL, headers={"Authorization": f"Bearer {new_token}"})
            try:
                with urllib.request.urlopen(req) as r:
                    result["downstream"] = json.load(r)
            except urllib.error.HTTPError as e:
                result["downstream"] = json.loads(e.read().decode())
                return self.reply(502, result)
        return self.reply(200, result)


if __name__ == "__main__":
    print(f"[{NAME}] listening on :{PORT} next={NEXT_URL or '-'} "
          f"accepts-delegation-from={ALLOWED_CALLER or 'anyone'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
