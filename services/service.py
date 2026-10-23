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
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ["SERVICE_NAME"]
SECRET = os.environ.get("CLIENT_SECRET", f"{NAME}-secret")
PORT = int(os.environ.get("PORT", "8081"))
KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("REALM", "rfc8693")
NEXT_URL = os.environ.get("NEXT_SERVICE_URL")
NEXT_CLIENT = os.environ.get("NEXT_CLIENT_ID")

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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self.reply(401, {"service": NAME, "error": "missing bearer token"})
        token = auth[7:]

        info = introspect(token)
        aud = info.get("aud") or []
        aud = [aud] if isinstance(aud, str) else aud
        if not info.get("active"):
            return self.reply(401, {"service": NAME, "error": "token not active"})
        if NAME not in aud:
            return self.reply(403, {"service": NAME, "error": f"token audience {aud} does not include {NAME}"})

        user = info.get("preferred_username") or info.get("sub")
        chain = actors(info.get("act"))
        call_path = [user] + list(reversed(chain)) + [NAME]
        print(f"[{NAME}] user={user} sub={info.get('sub')} called-by={chain[0] if chain else user} "
              f"path={' -> '.join(call_path)}", flush=True)

        result = {
            "service": NAME,
            "user": user,
            "sub": info.get("sub"),
            "immediate_caller": chain[0] if chain else user,
            "call_path": " -> ".join(call_path),
            "act": info.get("act"),
        }

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
    print(f"[{NAME}] listening on :{PORT} next={NEXT_URL or '-'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
