#!/usr/bin/env python3
"""Optional end-to-end check that drives a real browser through the web page.

  pip install playwright && playwright install chromium     # once
  python3 tests/e2e_browser.py                              # stack must be running (run-local.sh / docker compose)

Env: WEB_APP_URL (http://localhost:3000), CHROMIUM (path to an existing Chromium binary, optional),
     SCREENSHOTS (directory to save screenshots, optional)
"""
import os
import sys

from playwright.sync_api import sync_playwright

WEB_APP_URL = os.environ.get("WEB_APP_URL", "http://localhost:3000").rstrip("/")
SHOTS = os.environ.get("SCREENSHOTS")
results = []


def check(label, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    results.append(ok)


def shot(page, name):
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, name), full_page=True)


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM"))
    page = browser.new_page(viewport={"width": 1100, "height": 900})

    page.goto(WEB_APP_URL + "/")
    check("first visit redirects to the Keycloak login page", "/protocol/openid-connect/auth" in page.url)
    shot(page, "01-login.png")
    page.fill("#username", "alice")
    page.fill("#password", "alice")
    page.click("#kc-login")
    page.wait_for_load_state()

    check("Keycloak asks alice to let service-1 act on her behalf",
          "Allow service-1 to act on your behalf" in page.inner_text("body"))
    shot(page, "02-consent.png")
    page.click("#kc-login")  # "Yes"
    page.wait_for_url(WEB_APP_URL + "/")
    body = page.inner_text("body")
    check("back on the web page, signed in as alice", "Signed in as alice" in body)
    check("alice's token carries may_act for service-1", '"client_id": "service-1"' in body)
    shot(page, "03-home.png")

    page.click("text=Call service-1 → service-2")
    page.wait_for_selector(".hop >> nth=1")
    hops = page.locator(".hop").all_inner_texts()
    check("service-1 sees user alice, called by alice", "user (sub): alice · called by: alice" in hops[0])
    check("service-1 got a delegated token for service-2", "(delegation (subject_token + actor_token)): issued" in hops[0])
    check("service-2 sees user alice, called by service-1", "user (sub): alice · called by: service-1" in hops[1])
    shot(page, "04-service-1-to-service-2.png")

    page.click("text=Try one more hop")
    page.wait_for_selector("text=refused")
    hops = page.locator(".hop").all_inner_texts()
    check("stock Keycloak refuses the next exchange (service-2 -> service-3)",
          "Subject token with a delegation claim is not allowed" in hops[1])
    shot(page, "05-next-hop-refused.png")
    browser.close()

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
