#!/usr/bin/env python3
"""Generic demo microservice (stdlib only). Run N copies to form a chain.

For each request it:
  1. validates the bearer token via Keycloak introspection (must be active and addressed to this service)
  2. reports who the *user* is (sub) and who is calling on their behalf (the nested "act" chain)
  3. if asked to go further (?hops=N, N > 0) and NEXT_SERVICE_URL is set: exchanges the token (RFC 8693) for one
     whose audience is the next service and calls it with ?hops=N-1.
       - token's may_act names this service -> delegation exchange (subject_token + actor_token).
         Keycloak issues act={this service}.
       - otherwise -> standard token exchange (subject_token only). Keycloak refuses this for a token that
         already carries act/may_act, which is where the stock-Keycloak chain ends.

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


def exchange(subject_token, may_act):
    form = {
        "grant_type": TOKEN_EXCHANGE, "client_id": NAME, "client_secret": SECRET,
        "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE,
        "audience": NEXT_CLIENT,
    }
    if (may_act or {}).get("client_id") == NAME:
        mode = "delegation (subject_token + actor_token)"
        form.update(actor_token=own_token(), actor_token_type=ACCESS_TOKEN_TYPE)
    else:
        mode = "standard (subject_token only)"
    try:
        return mode, post_form(f"{OIDC}/token", form)["access_token"]
    except HttpError as e:
        e.mode = mode
        raise


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
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        hops = int(query.get("hops", ["0"])[0])
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
            "may_act": info.get("may_act"),
        }

        if NEXT_URL and hops > 0:
            try:
                mode, new_token = exchange(token, info.get("may_act"))
            except HttpError as e:
                result["token_exchange"] = {
                    "target": NEXT_CLIENT, "mode": e.mode, "status": e.status,
                    "error": json.loads(e.body) if e.body.startswith("{") else e.body}
                print(f"[{NAME}] token exchange for {NEXT_CLIENT} refused: {e.body}", flush=True)
                return self.reply(200, result)
            c = jwt_claims(new_token)
            result["token_exchange"] = {"target": NEXT_CLIENT, "mode": mode, "status": 200}
            result["exchanged_token_for_next_hop"] = {k: c.get(k) for k in ("sub", "preferred_username", "azp", "aud", "act")}
            req = urllib.request.Request(f"{NEXT_URL}?hops={hops - 1}", headers={"Authorization": f"Bearer {new_token}"})
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
