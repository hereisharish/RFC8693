#!/usr/bin/env python3
"""Configure a stock Keycloak 26.8+ realm for RFC 8693 delegation (no custom providers, no custom scopes).

  browser --login--> web-app --(user token, may_act=service-1)--> service-1
  service-1 --token exchange (subject_token + actor_token)--> token for service-2 with act={service-1}

Stdlib only. Idempotent: deletes and re-creates the realm on every run.

Env vars: KC_URL (default http://localhost:8080), KC_ADMIN / KC_ADMIN_PASSWORD (admin/admin), REALM (rfc8693),
          WEB_APP_URL (http://localhost:3000)
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
ADMIN = os.environ.get("KC_ADMIN", "admin")
ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "admin")
REALM = os.environ.get("REALM", "rfc8693")
WEB_APP_URL = os.environ.get("WEB_APP_URL", "http://localhost:3000").rstrip("/")

SERVICES = ["service-1", "service-2", "service-3"]
SECRET = "{}-secret"  # POC only: secret = "<client-id>-secret"
USER, USER_PASSWORD = "alice", "alice"
DELEGATION_SCOPE = "delegation:client"  # built in, created by Keycloak when token-exchange-delegation is on
DELEGATE = "service-1"                  # the service alice lets act on her behalf


def http(method, path, token=None, body=None, form=None, ok=(200, 201, 204)):
    headers = {}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(KC_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        if e.code in ok:
            return e.code, None
        raise SystemExit(f"{method} {path} -> {e.code}: {e.read().decode()}")


def admin_token():
    for _ in range(60):
        try:
            _, tok = http("POST", "/realms/master/protocol/openid-connect/token", form={
                "grant_type": "password", "client_id": "admin-cli",
                "username": ADMIN, "password": ADMIN_PASSWORD})
            return tok["access_token"]
        except (urllib.error.URLError, ConnectionError):
            print("waiting for Keycloak ...")
            time.sleep(3)
    sys.exit("Keycloak not reachable at " + KC_URL)


def main():
    t = admin_token()
    a = f"/admin/realms/{REALM}"

    # 1. Realm, with Fine-Grained Admin Permissions v2 (needed for the "delegate" permission)
    http("DELETE", a, t, ok=(204, 404))
    http("POST", "/admin/realms", t, {"realm": REALM, "enabled": True, "adminPermissionsEnabled": True})
    print(f"realm '{REALM}' created")

    # 2. End user
    http("POST", f"{a}/users", t, {
        "username": USER, "enabled": True, "email": "alice@example.com", "emailVerified": True,
        "firstName": "Alice", "lastName": "Example",
        "credentials": [{"type": "password", "value": USER_PASSWORD, "temporary": False}],
    })

    # 3. Clients
    #    web-app: the web page (server-side, confidential, authorization code + PKCE). consentRequired is needed
    #             because the built-in delegation scope is "always consent": alice approves the delegation herself.
    #    service-N: confidential clients with a service account (for the actor_token) and token exchange enabled.
    http("POST", f"{a}/clients", t, {
        "clientId": "web-app", "name": "Demo Web App", "publicClient": False, "secret": SECRET.format("web-app"),
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "consentRequired": True,
        "redirectUris": [f"{WEB_APP_URL}/*"], "webOrigins": [WEB_APP_URL],
        "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"{WEB_APP_URL}/*"},
        "fullScopeAllowed": False,
    })
    for s in SERVICES:
        http("POST", f"{a}/clients", t, {
            "clientId": s, "publicClient": False, "secret": SECRET.format(s),
            "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "attributes": {"standard.token.exchange.enabled": "true"},
            "fullScopeAllowed": False,
        })
    clients = {c["clientId"]: c for c in http("GET", f"{a}/clients?max=200", t)[1]}
    print("clients created:", ", ".join(["web-app"] + SERVICES))

    # 4. Built-in delegation scope on web-app. Requesting "delegation:client:service-1" at login shows alice a
    #    consent screen and puts may_act={sub,client_id:service-1} + aud=service-1 into her token.
    scopes = {s["name"]: s for s in http("GET", f"{a}/client-scopes", t)[1]}
    if DELEGATION_SCOPE not in scopes:
        sys.exit(f"client scope '{DELEGATION_SCOPE}' missing - start Keycloak with "
                 "--features=token-exchange-delegation,parameterized-scopes")
    http("PUT", f"{a}/clients/{clients['web-app']['id']}/optional-client-scopes/{scopes[DELEGATION_SCOPE]['id']}", t)

    # 5. Standard audience scopes: service-N may ask for a token whose audience is service-N+1
    #    (token exchange V2 only grants audiences the requesting client could get anyway).
    for caller, target in zip(SERVICES, SERVICES[1:]):
        name = f"audience-{target}"
        http("POST", f"{a}/client-scopes", t, {
            "name": name, "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
            "protocolMappers": [{
                "name": name, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.client.audience": target, "access.token.claim": "true",
                           "introspection.token.claim": "true"},
            }],
        })
        scope_id = next(s["id"] for s in http("GET", f"{a}/client-scopes", t)[1] if s["name"] == name)
        http("PUT", f"{a}/clients/{clients[caller]['id']}/default-client-scopes/{scope_id}", t)
        print(f"{caller} may request audience {target}")

    # 6. FGAP v2: service-1's service account may "delegate" (act on behalf of) users.
    #    Without this, "delegation:client:service-1" is refused at login.
    authz = f"{a}/clients/{clients['admin-permissions']['id']}/authz/resource-server"
    http("POST", f"{authz}/policy/client", t, {
        "name": "delegates", "logic": "POSITIVE", "clients": [clients[DELEGATE]["id"]],
    })
    policy = http("GET", f"{authz}/policy?name=delegates", t)[1][0]
    http("POST", f"{authz}/permission/scope", t, {
        "name": f"{DELEGATE}-may-act-for-users", "resourceType": "Users",
        "scopes": ["delegate"], "policies": [policy["id"]], "decisionStrategy": "UNANIMOUS",
    })
    print(f"FGAP 'delegate' permission on Users granted to {DELEGATE}")
    print("done.")


if __name__ == "__main__":
    main()
