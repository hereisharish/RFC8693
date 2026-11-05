#!/usr/bin/env python3
"""Local stand-in for Kong, driven by gateways/kong/kong.yaml (stdlib + PyYAML).

NOT Kong. It reproduces only the documented behaviour this POC relies on, so the services and the
Keycloak side can be tested without a Kong Enterprise licence:

  openid-connect   iss/exp check on the bearer token; if conditions.has_audience matches, an RFC 8693
                   exchange at token_endpoint as the configured client (subject_token from the bearer,
                   actor_token from the configured header, scope = request.scopes); then
                   audience_required on the token being forwarded. No signature check (Keycloak verifies
                   the subject token during the exchange; services introspect what they receive).
  request-transformer   remove.headers only.

Docker hostnames in kong.yaml (http://keycloak:8080, http://service-2:8082, ...) map to localhost.

Usage: python3 gateways/kong/standin.py [kong.yaml] [port]   (default port 8000)
"""
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

CONFIG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "kong.yaml")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def local(url):
    return re.sub(r"^http://[a-z0-9-]+:(\d+)", r"http://localhost:\1", url)


def load_routes(path):
    routes = []
    for svc in yaml.safe_load(open(path))["services"]:
        for r in svc.get("routes", []):
            for p in r["paths"]:
                routes.append({"name": r["name"], "path": p, "strip": r.get("strip_path", True),
                               "upstream": local(svc["url"]),
                               "plugins": {pl["name"]: pl["config"] for pl in r.get("plugins", [])}})
    return sorted(routes, key=lambda r: -len(r["path"]))


ROUTES = load_routes(CONFIG)


class Reject(Exception):
    def __init__(self, status, message, detail=None):
        super().__init__(message)
        self.status, self.message, self.detail = status, message, detail


def claims(token):
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        raise Reject(401, "invalid token")


def audiences(c):
    aud = c.get("aud") or []
    return [aud] if isinstance(aud, str) else aud


def openid_connect(cfg, headers):
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise Reject(401, "missing bearer token")
    token = auth[7:]
    c = claims(token)
    if c.get("iss") != cfg["issuer"] or c.get("exp", 0) < time.time():
        raise Reject(401, "invalid issuer or expired token")

    for issuer in cfg.get("token_exchange", {}).get("subject_token_issuers", []):
        wanted = (issuer.get("conditions") or {}).get("has_audience")
        if issuer["issuer"] != c["iss"] or (wanted and not set(wanted) & set(audiences(c))):
            continue
        req = cfg["token_exchange"].get("request", {})
        form = {"grant_type": TOKEN_EXCHANGE, "client_id": cfg["client_id"][0],
                "client_secret": cfg["client_secret"][0],
                "subject_token": token, "subject_token_type": ACCESS_TOKEN_TYPE}
        if req.get("scopes"):
            form["scope"] = " ".join(req["scopes"])
        actor = req.get("actor_token")
        if actor and headers.get(actor["header_name"]):
            form["actor_token"] = headers[actor["header_name"]]
            form["actor_token_type"] = actor.get("type", ACCESS_TOKEN_TYPE)
        try:
            with urllib.request.urlopen(urllib.request.Request(
                    local(cfg["token_endpoint"]), urllib.parse.urlencode(form).encode())) as r:
                token = json.load(r)["access_token"]
        except urllib.error.HTTPError as e:
            raise Reject(401, "token exchange failed", json.loads(e.read().decode() or "{}"))
        c = claims(token)
        break

    required = cfg.get("audience_required")
    if required and not set(required) & set(audiences(c)):
        raise Reject(403, f"token audience {audiences(c)} does not include {required}")
    headers["Authorization"] = f"Bearer {token}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def reply(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self):
        url = urllib.parse.urlparse(self.path)
        route = next((r for r in ROUTES if url.path == r["path"] or url.path.startswith(r["path"].rstrip("/") + "/")), None)
        if not route:
            return self.reply(404, {"message": "no Route matched with those values"})
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        try:
            if "openid-connect" in route["plugins"]:
                openid_connect(route["plugins"]["openid-connect"], headers)
        except Reject as e:
            print(f"[kong] {route['name']}: {e.status} {e.message} {e.detail or ''}", flush=True)
            return self.reply(e.status, {"message": e.message, "detail": e.detail})
        for h in route["plugins"].get("request-transformer", {}).get("remove", {}).get("headers", []):
            headers = {k: v for k, v in headers.items() if k.lower() != h.lower()}

        rest = url.path[len(route["path"].rstrip("/")):] if route["strip"] else url.path
        target = route["upstream"].rstrip("/") + (rest or "/") + (f"?{url.query}" if url.query else "")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        try:
            with urllib.request.urlopen(urllib.request.Request(target, body, headers, method=self.command)) as r:
                return self.reply(r.status, r.read(), r.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as e:
            return self.reply(e.code, e.read(), e.headers.get("Content-Type", "application/json"))

    do_GET = do_POST = handle_any


if __name__ == "__main__":
    print(f"[kong stand-in] :{PORT} routes: {', '.join(r['path'] for r in ROUTES)}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
