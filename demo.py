#!/usr/bin/env python3
"""End-to-end demo: alice -> service-1 -> service-2 -> service-3 -> service-4, plus negative checks."""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("REALM", "rfc8693")
SERVICE_1 = os.environ.get("SERVICE_1_URL", "http://localhost:8081/")
SERVICE_3 = os.environ.get("SERVICE_3_URL", "http://localhost:8083/")
TOKEN_URL = f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token"


def post(form):
    req = urllib.request.Request(TOKEN_URL, urllib.parse.urlencode(form).encode())
    try:
        with urllib.request.urlopen(req) as r:
            return 200, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def claims(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def banner(text):
    print("\n" + "=" * 78 + f"\n{text}\n" + "=" * 78)


def check(label, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    return ok


# 1. user logs in to the front end, asking that service-1 may act on her behalf
banner("1. alice logs in (web-app) with scope 'delegate-to:service-1'")
status, tok = post({"grant_type": "password", "client_id": "web-app", "username": "alice",
                    "password": "alice", "scope": "openid delegate-to:service-1"})
if status != 200:
    sys.exit(f"login failed: {tok}")
user_token = tok["access_token"]
print(json.dumps({k: claims(user_token).get(k) for k in ("sub", "preferred_username", "azp", "aud", "may_act")}, indent=2))

# 2. call the chain
banner("2. alice calls service-1 (which calls service-2 -> service-3 -> service-4)")
status, body = get(SERVICE_1, user_token)
print(json.dumps(body, indent=2))

results = []
hop = body
paths = []
while hop:
    paths.append(hop)
    hop = hop.get("downstream")
last = paths[-1]

banner("3. Assertions")
results.append(check("HTTP 200 end to end", status == 200))
results.append(check("4 hops reached", [h["service"] for h in paths] == ["service-1", "service-2", "service-3", "service-4"]))
results.append(check("every hop sees the user as alice", all(h["user"] == "alice" for h in paths)))
results.append(check("service-4 call_path = alice -> service-1 -> service-2 -> service-3 -> service-4",
                     last["call_path"] == "alice -> service-1 -> service-2 -> service-3 -> service-4"))
results.append(check("service-4 immediate caller is service-3", last["immediate_caller"] == "service-3"))

# 4. negative checks
banner("4. Negative checks")
# a) alice's token was only issued for service-1, so service-3 must refuse it
status, body = get(SERVICE_3, user_token)
results.append(check(f"service-3 rejects alice's service-1 token directly (HTTP {status}: {body.get('error')})",
                     status in (401, 403)))

# b) a token whose may_act names service-2 cannot be exchanged by service-3
s1 = {"client_id": "service-1", "client_secret": "service-1-secret"}
s3 = {"client_id": "service-3", "client_secret": "service-3-secret"}
s1_actor = post({"grant_type": "client_credentials", **s1})[1]["access_token"]
_, t12 = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", **s1,
               "subject_token": user_token, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
               "actor_token": s1_actor, "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
               "scope": "delegate-to:service-2"})
s3_actor = post({"grant_type": "client_credentials", **s3})[1]["access_token"]
status, err = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", **s3,
                    "subject_token": t12["access_token"], "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "actor_token": s3_actor, "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "scope": "delegate-to:service-4"})
results.append(check(f"service-3 cannot exchange a token meant for service-2 (HTTP {status}: {err.get('error_description')})",
                     status in (400, 403)))

# c) service-1 cannot pretend to be service-2 by sending its own actor token to act on a may_act=service-2 token
s2_status, err2 = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", **s1,
                        "subject_token": t12["access_token"], "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "actor_token": s1_actor, "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "scope": "delegate-to:service-3"})
results.append(check(f"service-1 cannot re-use the service-2 token (HTTP {s2_status}: {err2.get('error_description')})",
                     s2_status in (400, 403)))

# 5. The approved call graph: only service-N may delegate to service-N+1. Skipping a hop must fail at
#    issuance, so a service cannot even obtain a token for a service it is not allowed to call.
banner("5. Approved call graph (1 -> 2 -> 3 -> 4 only)")


def exchange_as(caller, subject_token, target):
    creds = {"client_id": caller, "client_secret": f"{caller}-secret"}
    actor = post({"grant_type": "client_credentials", **creds})[1]["access_token"]
    return post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", **creds,
                 "subject_token": subject_token, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                 "actor_token": actor, "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
                 "scope": f"delegate-to:{target}"})


for caller, target in (("service-1", "service-3"), ("service-1", "service-4"), ("service-2", "service-4")):
    subject = user_token if caller == "service-1" else t12["access_token"]
    st, body = exchange_as(caller, subject, target)
    blocked = st in (400, 403) and "not an approved hop" in (body.get("error_description") or "")
    results.append(check(f"{caller} cannot mint a token for {target} (HTTP {st}: {body.get('error_description')})",
                         blocked))

# the approved hops must still work, or the rule is simply breaking everything
st, body = exchange_as("service-1", user_token, "service-2")
results.append(check("service-1 -> service-2 is still allowed (the approved hop)", st == 200))

# and even with a token in hand, service-4 refuses a caller that is not service-3
status, body = get(os.environ.get("SERVICE_4_URL", "http://localhost:8084/"), user_token)
results.append(check(f"service-4 refuses alice's token presented directly (HTTP {status}: {body.get('error')})",
                     status in (401, 403)))

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
