#!/usr/bin/env python3
"""Configure a Keycloak 26.8+ realm for RFC 8693 delegation chains (user -> service-1 -> ... -> service-4).

Stdlib only. Idempotent: deletes and re-creates the realm on every run.

Env vars: KC_URL (default http://localhost:8080), KC_ADMIN / KC_ADMIN_PASSWORD (admin/admin), REALM (rfc8693)
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

SERVICES = ["service-1", "service-2", "service-3", "service-4"]
SERVICE_SECRET = "{}-secret"  # POC only: secret = "<client-id>-secret"
USER, USER_PASSWORD = "alice", "alice"
DELEGATION_SCOPE = "delegate-to"
PORTAL_ORIGIN = os.environ.get("PORTAL_ORIGIN", "http://localhost:8000")  # where ui/index.html is served


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
            return resp.status, (json.loads(raw) if raw else None), resp.headers
    except urllib.error.HTTPError as e:
        if e.code in ok:
            return e.code, None, e.headers
        raise SystemExit(f"{method} {path} -> {e.code}: {e.read().decode()}")


def admin_token():
    for _ in range(60):
        try:
            _, tok, _ = http("POST", "/realms/master/protocol/openid-connect/token", form={
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
    http("POST", "/admin/realms", t, {
        "realm": REALM, "enabled": True,
        "adminPermissionsEnabled": True,
        "accessTokenLifespan": 1800,  # long enough to survive a live demo; the UI also silently refreshes
    })
    print(f"realm '{REALM}' created")

    # 1b. Event auditing. TOKEN_EXCHANGE events are the issuance record behind every hop: each one
    #     carries details.actor (who asked), details.audience (which service the token is for) and
    #     details.username (on behalf of whom). TOKEN_EXCHANGE_ERROR records the refusals.
    http("PUT", f"{a}/events/config", t, {
        "eventsEnabled": True,
        "eventsExpiration": 7200,
        "eventsListeners": ["jboss-logging"],
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": False,
    })
    print("event auditing enabled (login, token exchange, and their errors)")

    # 2. End user
    http("POST", f"{a}/users", t, {
        "username": USER, "enabled": True, "email": "alice@example.com", "emailVerified": True,
        "firstName": "Alice", "lastName": "Example",
        "credentials": [{"type": "password", "value": USER_PASSWORD, "temporary": False}],
    })

    # 3. Clients
    #    web-app: the front end the user logs in to. The ui/ portal uses authorization code + PKCE
    #             against this client; directAccessGrants stays on only so demo.py can stay scriptable.
    #    service-N: confidential clients with a service account and standard token exchange enabled
    #    webOrigins must be an explicit origin, not "+": "+" means "derive the CORS origins from the
    #    redirect URIs", and Keycloak cannot derive one from the wildcard port in http://localhost:*.
    #    The preflight still passes, but the real POST /token is refused with {"error":"Invalid origin"},
    #    which surfaces in the browser as an opaque "TypeError: Failed to fetch".
    http("POST", f"{a}/clients", t, {
        "clientId": "web-app", "publicClient": True, "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True, "redirectUris": ["http://localhost:*"],
        "webOrigins": [PORTAL_ORIGIN],
        "fullScopeAllowed": False,
        "attributes": {"post.logout.redirect.uris": "+"},  # let the portal's sign-out return to itself
    })
    for s in SERVICES:
        http("POST", f"{a}/clients", t, {
            "clientId": s, "publicClient": False, "secret": SERVICE_SECRET.format(s),
            "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "attributes": {"standard.token.exchange.enabled": "true"},
        })
    clients = {c["clientId"]: c for c in http("GET", f"{a}/clients?max=200", t)[1]}
    print("clients created:", ", ".join(["web-app"] + SERVICES))

    # 4. Delegation scope.
    #    Keycloak creates a built-in parameterized scope "delegation:client" when the feature is on. Requesting
    #    "delegation:client:<client-id>" puts may_act={sub,client_id} and aud=<client-id> into the token.
    #    The built-in one is "always consent", which can never be satisfied inside a token-exchange request, so
    #    it only works for the first, interactive hop. For a multi-hop chain we clone it as "delegate-to"
    #    (same type and mappers, no always-consent). Delegation is still guarded by the FGAP "delegate" permission.
    scopes = {s["name"]: s for s in http("GET", f"{a}/client-scopes", t)[1]}
    if "delegation:client" not in scopes:
        sys.exit("client scope 'delegation:client' missing - start Keycloak with "
                 "--features=token-exchange-delegation,parameterized-scopes")
    builtin = http("GET", f"{a}/client-scopes/{scopes['delegation:client']['id']}", t)[1]
    mappers = [{k: v for k, v in m.items() if k != "id"} for m in builtin.get("protocolMappers", [])]
    http("POST", f"{a}/client-scopes", t, {
        "name": DELEGATION_SCOPE, "protocol": "openid-connect",
        "description": "RFC 8693 delegation: delegate-to:<client-id> adds may_act + aud for that client",
        "attributes": {
            "is.parameterized.scope": "true",
            "parameterized.scope.type": builtin["attributes"]["parameterized.scope.type"],  # client-delegation
            "include.in.token.scope": "true",
            "display.on.consent.screen": "false",
        },
        "protocolMappers": mappers,
    })
    scope_id = next(s["id"] for s in http("GET", f"{a}/client-scopes", t)[1] if s["name"] == DELEGATION_SCOPE)
    for cid in ["web-app"] + SERVICES:
        http("PUT", f"{a}/clients/{clients[cid]['id']}/optional-client-scopes/{scope_id}", t)
    print(f"client scope '{DELEGATION_SCOPE}' created with mappers:", ", ".join(m["name"] for m in mappers))

    # 5. FGAP v2: allow the service clients' service accounts to "delegate" for users.
    #    This is what decides whether "delegation:client:service-N" may be granted for a user.
    perm_client = clients["admin-permissions"]["id"]
    authz = f"{a}/clients/{perm_client}/authz/resource-server"
    http("POST", f"{authz}/policy/client", t, {
        "name": "delegating-services", "logic": "POSITIVE",
        "clients": [clients[s]["id"] for s in SERVICES],
    })
    policy = http("GET", f"{authz}/policy?name=delegating-services", t)[1][0]
    http("POST", f"{authz}/permission/scope", t, {
        "name": "services-may-delegate-for-all-users", "resourceType": "Users",
        "scopes": ["delegate"], "policies": [policy["id"]],
        "decisionStrategy": "UNANIMOUS",
    })
    print("FGAP permission 'delegate' on Users granted to", ", ".join(SERVICES))
    print("done.")


if __name__ == "__main__":
    main()
