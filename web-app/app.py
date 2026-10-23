#!/usr/bin/env python3
"""Demo web page (stdlib only): OIDC authorization code + PKCE login against Keycloak, then calls service-1.

  GET /           -> not logged in: redirect to Keycloak login (+ consent: "let service-1 act for you")
  GET /callback   -> code -> tokens, kept server side; browser only gets a session cookie
  GET /api/call   -> calls service-1 with alice's access token (?hops=1: service-1 -> service-2, ?hops=2: one more)
  GET /logout     -> Keycloak logout

Env: PORT (3000), WEB_APP_URL (http://localhost:3000), KC_PUBLIC_URL (what the browser uses, http://localhost:8080),
     KC_URL (what this server uses, defaults to KC_PUBLIC_URL), REALM, CLIENT_ID, CLIENT_SECRET, SERVICE_1_URL
"""
import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "3000"))
WEB_APP_URL = os.environ.get("WEB_APP_URL", "http://localhost:3000").rstrip("/")
KC_PUBLIC_URL = os.environ.get("KC_PUBLIC_URL", "http://localhost:8080").rstrip("/")
KC_URL = os.environ.get("KC_URL", KC_PUBLIC_URL).rstrip("/")
REALM = os.environ.get("REALM", "rfc8693")
CLIENT_ID = os.environ.get("CLIENT_ID", "web-app")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "web-app-secret")
SERVICE_1_URL = os.environ.get("SERVICE_1_URL", "http://localhost:8081/")
DELEGATE = os.environ.get("DELEGATE_CLIENT_ID", "service-1")

SCOPE = f"openid profile delegation:client:{DELEGATE}"
REDIRECT_URI = f"{WEB_APP_URL}/callback"
AUTHORIZE = f"{KC_PUBLIC_URL}/realms/{REALM}/protocol/openid-connect/auth"
LOGOUT = f"{KC_PUBLIC_URL}/realms/{REALM}/protocol/openid-connect/logout"
TOKEN = f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token"

pending = {}   # state -> {verifier, nonce}
sessions = {}  # session id -> token response (+ expires_at)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def claims(jwt):
    p = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def token_request(form):
    form = {**form, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}
    req = urllib.request.Request(TOKEN, urllib.parse.urlencode(form).encode())
    with urllib.request.urlopen(req) as r:
        tok = json.load(r)
    tok["expires_at"] = time.time() + tok["expires_in"] - 10
    return tok


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Delegation Demo</title>
<style>
  :root {{ --bg:#f7f7f8; --card:#fff; --fg:#1d1d1f; --muted:#6b6b76; --line:#e2e2e8; --accent:#3d5afe; --ok:#1b873f; --bad:#c62828; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#141418; --card:#1e1e24; --fg:#ececf1; --muted:#9a9aa6; --line:#33333d; --accent:#8c9eff; --ok:#5fd17f; --bad:#ff6b6b; }} }}
  body {{ margin:0; font:15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); }}
  main {{ max-width:960px; margin:0 auto; padding:24px 16px; }}
  header {{ display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }}
  h1 {{ font-size:22px; margin:0; }} h2 {{ font-size:16px; margin:0 0 8px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin-top:16px; }}
  .muted {{ color:var(--muted); }}
  button {{ font:inherit; padding:8px 14px; border-radius:8px; border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer; margin:4px 8px 4px 0; }}
  button.secondary {{ background:transparent; color:var(--accent); }}
  a {{ color:var(--accent); }}
  pre {{ background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; font-size:13px; max-height:420px; }}
  .chain {{ display:flex; flex-wrap:wrap; align-items:center; gap:6px; margin:8px 0; }}
  .node {{ border:1px solid var(--line); border-radius:999px; padding:2px 10px; background:var(--bg); }}
  .node.user {{ border-color:var(--ok); color:var(--ok); }}
  .hop {{ border-left:3px solid var(--line); padding:4px 12px; margin:10px 0; }}
  .ok {{ color:var(--ok); }} .bad {{ color:var(--bad); }}
  code {{ font-size:13px; }}
</style></head>
<body><main>
<header><h1>Delegation demo</h1><div>Signed in as <b>{user}</b> · <a href="/logout">Log out</a></div></header>

<div class="card">
  <h2>1. Your token (from Keycloak login)</h2>
  <p class="muted">Issued to <code>web-app</code>. Because you consented, it names <code>{delegate}</code> in
  <code>may_act</code>: only {delegate} may exchange it to act on your behalf.</p>
  <pre>{token}</pre>
</div>

<div class="card">
  <h2>2. Call the services</h2>
  <button onclick="call(1)">Call service-1 → service-2</button>
  <button class="secondary" onclick="call(2)">Try one more hop: service-2 → service-3</button>
  <div id="result" class="muted">Each hop shows who the user is and who called on their behalf.</div>
</div>

<script>
const esc = s => String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
async function call(hops) {{
  const out = document.getElementById('result');
  out.textContent = 'Calling…';
  const r = await fetch('/api/call?hops=' + hops);
  if (r.status === 401) {{ location.href = '/login'; return; }}
  const data = await r.json();
  let h = '', hop = data;
  while (hop) {{
    const nodes = hop.call_path ? hop.call_path.split(' -> ') : [];
    h += '<div class="hop"><b>' + esc(hop.service || 'error') + '</b>';
    if (hop.error) h += ' <span class="bad">' + esc(hop.error) + '</span>';
    if (hop.user) h += '<div>user (sub): <b>' + esc(hop.user) + '</b> · called by: <b>' + esc(hop.immediate_caller) + '</b></div>'
      + '<div class="chain">' + nodes.map((n, i) => '<span class="node' + (i === 0 ? ' user' : '') + '">' + esc(n) + '</span>').join(' → ') + '</div>';
    const te = hop.token_exchange;
    if (te) h += '<div>token exchange for <code>' + esc(te.target) + '</code> (' + esc(te.mode) + '): '
      + (te.status === 200 ? '<span class="ok">issued</span>' : '<span class="bad">refused, HTTP ' + te.status + ': '
      + esc((te.error && (te.error.error_description || te.error.error)) || te.error) + '</span>') + '</div>';
    h += '</div>';
    hop = hop.downstream;
  }}
  out.innerHTML = h + '<details><summary>Raw response</summary><pre>' + esc(JSON.stringify(data, null, 2)) + '</pre></details>';
}}
</script>
</main></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def redirect(self, url, cookie=None):
        self.send_response(302)
        self.send_header("Location", url)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def send(self, status, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def session(self):
        sid = SimpleCookie(self.headers.get("Cookie", "")).get("sid")
        tok = sessions.get(sid.value) if sid else None
        if tok and tok["expires_at"] < time.time():
            try:
                fresh = token_request({"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]})
                fresh.setdefault("id_token", tok.get("id_token"))
                sessions[sid.value] = tok = fresh
            except urllib.error.HTTPError:
                sessions.pop(sid.value, None)
                tok = None
        return tok

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)

        if url.path == "/login":
            state, verifier, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(48), secrets.token_urlsafe(16)
            pending[state] = {"verifier": verifier, "nonce": nonce}
            challenge = b64url(hashlib.sha256(verifier.encode()).digest())
            return self.redirect(AUTHORIZE + "?" + urllib.parse.urlencode({
                "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "scope": SCOPE,
                "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}))

        if url.path == "/callback":
            if "error" in q:
                return self.send(400, f"<p>Login failed: {html.escape(q['error'][0])} "
                                      f"{html.escape(q.get('error_description', [''])[0])}</p><a href='/login'>Retry</a>")
            req = pending.pop(q.get("state", [""])[0], None)
            if not req:
                return self.redirect("/login")
            try:
                tok = token_request({"grant_type": "authorization_code", "code": q["code"][0],
                                     "redirect_uri": REDIRECT_URI, "code_verifier": req["verifier"]})
            except urllib.error.HTTPError as e:
                return self.send(400, f"<pre>{html.escape(e.read().decode())}</pre>")
            if claims(tok["id_token"]).get("nonce") != req["nonce"]:
                return self.send(400, "nonce mismatch")
            sid = secrets.token_urlsafe(32)
            sessions[sid] = tok
            return self.redirect("/", f"sid={sid}; HttpOnly; SameSite=Lax; Path=/")

        if url.path == "/logout":
            sid = SimpleCookie(self.headers.get("Cookie", "")).get("sid")
            tok = sessions.pop(sid.value, None) if sid else None
            params = {"client_id": CLIENT_ID, "post_logout_redirect_uri": WEB_APP_URL + "/"}
            if tok and tok.get("id_token"):
                params["id_token_hint"] = tok["id_token"]
            return self.redirect(LOGOUT + "?" + urllib.parse.urlencode(params), "sid=; Max-Age=0; Path=/")

        tok = self.session()

        if url.path == "/api/call":
            if not tok:
                return self.send(401, json.dumps({"error": "not logged in"}), "application/json")
            hops = q.get("hops", ["1"])[0]
            req = urllib.request.Request(f"{SERVICE_1_URL}?hops={urllib.parse.quote(hops)}",
                                         headers={"Authorization": f"Bearer {tok['access_token']}"})
            try:
                with urllib.request.urlopen(req) as r:
                    return self.send(200, r.read().decode(), "application/json")
            except urllib.error.HTTPError as e:
                return self.send(e.code, e.read().decode(), "application/json")

        if url.path == "/":
            if not tok:
                return self.redirect("/login")
            c = claims(tok["access_token"])
            shown = {k: c.get(k) for k in ("sub", "preferred_username", "azp", "aud", "scope", "may_act")}
            return self.send(200, PAGE.format(user=html.escape(c.get("preferred_username", "?")),
                                              delegate=html.escape(DELEGATE),
                                              token=html.escape(json.dumps(shown, indent=2))))

        self.send(404, "not found", "text/plain")


if __name__ == "__main__":
    print(f"[web-app] {WEB_APP_URL} (Keycloak: browser {KC_PUBLIC_URL}, backchannel {KC_URL})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
