#!/usr/bin/env python3
"""Consolidated audit picture for the RFC 8693 delegation chain.

Two independent records, side by side:

  1. ISSUANCE  - Keycloak's own event log. Every token exchange is a TOKEN_EXCHANGE event carrying
                 who asked (actor), which service the token was minted for (audience), and on whose
                 behalf (username). Refusals land as TOKEN_EXCHANGE_ERROR.
  2. USE       - what each service actually saw and decided, read from its GET /audit endpoint:
                 the user, the delegation chain in the token, and allow/deny with a reason.

Together they answer "who asked for access to what, for whom, and was it granted" from both the
issuer's side and the resource's side, with no reliance on anything a caller claimed about itself.

Usage:
  python3 audit.py              # the full picture
  python3 audit.py --issuance   # Keycloak events only
  python3 audit.py --use        # service-side records only
  python3 audit.py --since 10   # only the last 10 minutes of Keycloak events

Env: KC_URL, REALM, KC_ADMIN, KC_ADMIN_PASSWORD, SERVICE_URLS (comma separated)
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC_URL = os.environ.get("KC_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("REALM", "rfc8693")
ADMIN = os.environ.get("KC_ADMIN", "admin")
ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "admin")
SERVICE_URLS = os.environ.get(
    "SERVICE_URLS",
    "http://localhost:8081/,http://localhost:8082/,http://localhost:8083/,http://localhost:8084/",
).split(",")

EXCHANGE_TYPES = ("TOKEN_EXCHANGE", "TOKEN_EXCHANGE_ERROR")
LOGIN_TYPES = ("LOGIN", "CODE_TO_TOKEN", "LOGIN_ERROR")


def get_json(url, token=None):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def admin_token():
    body = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN, "password": ADMIN_PASSWORD}).encode()
    with urllib.request.urlopen(urllib.request.Request(f"{KC_URL}/realms/master/protocol/openid-connect/token", body)) as r:
        return json.load(r)["access_token"]


def rule(title):
    print(f"\n\033[1m{title}\033[0m\n" + "-" * 108)


def issuance(since_minutes=None):
    """Keycloak's record: who requested a token, for which service, on whose behalf."""
    try:
        t = admin_token()
    except urllib.error.URLError as e:
        sys.exit(f"cannot reach Keycloak at {KC_URL}: {e}")

    base = f"{KC_URL}/admin/realms/{REALM}/events"
    q = {"max": 200}
    if since_minutes:
        # dateFrom is day-granular in Keycloak; filter precisely on the client side below.
        q["dateFrom"] = time.strftime("%Y-%m-%d", time.localtime(time.time() - since_minutes * 60))
    try:
        events = get_json(f"{base}?{urllib.parse.urlencode(q)}", t)
    except urllib.error.HTTPError as e:
        sys.exit(f"could not read events ({e.code}). Is eventsEnabled set on the realm? "
                 f"Re-run keycloak/setup_realm.py")

    if since_minutes:
        cutoff = (time.time() - since_minutes * 60) * 1000
        events = [e for e in events if e.get("time", 0) >= cutoff]

    if not events:
        print("  (no events recorded yet - run the demo or click through the portal first)")
        return

    rule("1. ISSUANCE - Keycloak event log: who was given a token for what, on whose behalf")
    print(f"  {'time':8}  {'event':14} {'actor':12} {'on behalf of':13} {'token minted for':17} outcome")
    for e in sorted(events, key=lambda x: x.get("time", 0)):
        if e["type"] not in EXCHANGE_TYPES + LOGIN_TYPES:
            continue
        d = e.get("details") or {}
        at = time.strftime("%H:%M:%S", time.localtime(e["time"] / 1000))
        actor = d.get("actor") or e.get("clientId") or "-"
        user = d.get("username") or ("-" if not e.get("userId") else e["userId"][:8])
        target = d.get("audience") or "-"
        if e["type"].endswith("_ERROR"):
            outcome = f"\033[31mREFUSED  {e.get('error') or d.get('reason') or ''}\033[0m"
            if d.get("rejected_hop"):
                outcome += f" ({d['rejected_hop']})"
        else:
            outcome = "\033[32mgranted\033[0m"
        label = {"TOKEN_EXCHANGE": "exchange", "TOKEN_EXCHANGE_ERROR": "exchange",
                 "CODE_TO_TOKEN": "login", "LOGIN": "login", "LOGIN_ERROR": "login"}[e["type"]]
        print(f"  {at:8}  {label:14} {actor:12} {user:13} {target:17} {outcome}")

    ex = [e for e in events if e["type"] in EXCHANGE_TYPES]
    granted = sum(1 for e in ex if e["type"] == "TOKEN_EXCHANGE")
    print(f"\n  {len(ex)} delegation requests: {granted} granted, {len(ex) - granted} refused")


def use():
    """Each service's record: what it saw in the token and what it decided."""
    rule("2. USE - what each service saw, and what it allowed or refused")
    print(f"  {'time':8}  {'service':22} {'user':7} {'called by':12} {'delegation chain':40} decision")
    rows, reachable = [], 0
    for url in SERVICE_URLS:
        url = url.strip().rstrip("/")
        if not url:
            continue
        try:
            body = get_json(f"{url}/audit")
            reachable += 1
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"  (could not read {url}/audit: {e})")
            continue
        for entry in body.get("entries", []):
            rows.append((entry, body.get("approved_caller")))

    if not rows:
        print("  (no requests recorded yet)" if reachable else "  (no services reachable)")
        return

    for entry, approved in sorted(rows, key=lambda r: r[0].get("ts", 0)):
        chain = " -> ".join(entry.get("delegation_chain") or []) or "-"
        label = f"{entry.get('title') or entry['service']} ({entry['service']})"
        if entry["decision"] == "allow":
            decision = "\033[32mallow\033[0m"
        else:
            decision = f"\033[31mDENY\033[0m  {entry.get('reason', '')}"
        at = time.strftime("%H:%M:%S", time.localtime(entry.get("ts", 0) / 1000))
        print(f"  {at:8}  {label:22} {str(entry.get('user') or '-'):7} "
              f"{str(entry.get('called_by') or '-'):12} {chain:40} {decision}")

    denies = sum(1 for e, _ in rows if e["decision"] != "allow")
    print(f"\n  {len(rows)} requests handled: {len(rows) - denies} allowed, {denies} refused")

    rule("3. The approved call graph each service enforces")
    for url in SERVICE_URLS:
        url = url.strip().rstrip("/")
        if not url:
            continue
        try:
            body = get_json(f"{url}/audit")
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue
        approved = body.get("approved_caller")
        who = f"only accepts delegation from \033[1m{approved}\033[0m" if approved \
            else "called directly by the user (no delegation expected)"
        print(f"  {body.get('title') or body['service']:14} ({body['service']}): {who}")


def main():
    args = sys.argv[1:]
    since = None
    if "--since" in args:
        since = int(args[args.index("--since") + 1])
    want_issuance = "--use" not in args
    want_use = "--issuance" not in args

    print(f"\n\033[1mAudit picture for realm '{REALM}'\033[0m  ({KC_URL})")
    if want_issuance:
        issuance(since)
    if want_use:
        use()
    print()


if __name__ == "__main__":
    main()
