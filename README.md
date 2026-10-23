# RFC 8693 delegation on stock Keycloak 26.8.1 (POC, no customization)

The POC uses the stock Keycloak image or distribution with **no extensions and no custom scopes**. It
only needs two built-in features turned on and some admin configuration.

```
browser ──login──► Keycloak ──token──► web page ──► service-1 ──token exchange──► service-2
```

1. Open the web page (http://localhost:3000). It redirects you to the **Keycloak login page**.
2. Keycloak shows a consent screen: **"Allow service-1 to act on your behalf?"**. Click **Yes**.
3. You land back on the page. The initial token (issued to `web-app`) has `sub=alice` and
   `may_act={client_id: service-1}`.
4. Click **Call service-1 → service-2**. service-1 exchanges alice's token
   (RFC 8693: `subject_token` + `actor_token`) for a new token for service-2:

```json
{
  "sub": "<alice-id>", "preferred_username": "alice",
  "azp": "service-1",
  "aud": "service-2",
  "act": { "client_id": "service-1", "sub": "<service-1 service-account id>" }
}
```

service-2 knows the **user is alice** (`sub`) and that **service-1 is calling on her behalf** (`act`).

## Run it

**Docker** (stock `quay.io/keycloak/keycloak:26.8.1`):

```bash
docker compose up -d
docker compose logs -f keycloak-setup     # wait for "done."
# open http://localhost:3000 and log in as alice / alice
```

**Without Docker** (needs Java 21 and Python 3; downloads the stock Keycloak distribution):

```bash
./run-local.sh            # then open http://localhost:3000 (alice / alice)
./run-local.sh stop
```

**Optional automated browser test** (needs `pip install playwright && playwright install chromium`):

```bash
python3 tests/e2e_browser.py
```

It logs in through the real Keycloak pages, consents, clicks both buttons, and checks 8 things.

Admin console: http://localhost:8080/admin (admin/admin), realm `rfc8693`.

## What is configured (all built in)

| Keycloak piece | Purpose |
|---|---|
| Feature `token-exchange-delegation` (preview) + `parameterized-scopes` (preview) | Lets token exchange take an `actor_token`. Keycloak checks the subject token's `may_act` against the actor and writes `act` into the new token |
| Built-in client scope `delegation:client` (optional scope on `web-app`) | Requesting `delegation:client:service-1` at login shows the consent screen. It adds `may_act` and `aud=service-1` to alice's token |
| `web-app` client: confidential, authorization code + PKCE, **consent required** | The web page. The delegation scope is "always consent", so alice approves it herself on every login |
| `service-N` clients: service account + `standard.token.exchange.enabled` | The service account gives each service its own `actor_token` |
| Client scope `audience-service-2` (standard audience mapper) on service-1 | Lets service-1 request a token whose audience is service-2 |
| Fine-Grained Admin Permissions v2: `delegate` on Users, for service-1 | Decides which clients may be named in `delegation:client:<client>`. Without it, login with that scope is refused |

All of this is set by `keycloak/setup_realm.py` through the admin REST API.

### The exchange service-1 performs

```
POST /realms/rfc8693/protocol/openid-connect/token
  grant_type         = urn:ietf:params:oauth:grant-type:token-exchange
  client_id/secret   = service-1
  subject_token      = alice's token (may_act must name service-1)
  subject_token_type = urn:ietf:params:oauth:token-type:access_token
  actor_token        = service-1's own client_credentials token
  actor_token_type   = urn:ietf:params:oauth:token-type:access_token
  audience           = service-2
```

## What stock Keycloak 26.8.1 does **not** do (yet)

The second button, **"Try one more hop: service-2 → service-3"**, shows where stock Keycloak stops.

* **Only one delegated hop.** The token service-2 receives has `act` but no `may_act` for the next hop, so
  service-2 cannot do another delegation exchange. A standard exchange (without `actor_token`) is refused
  too. The page shows Keycloak's error:
  `Subject token with a delegation claim is not allowed for standard token exchange`.
  * A `may_act` for the next hop could only come from requesting `delegation:client:service-3` during the
    exchange. That scope is "always consent", and consent can only be given in a browser login, never
    inside a token-exchange request. Keycloak rejects it.
* **No nested `act` chain.** Even with a further hop, Keycloak builds `act` from the subject token's
  `may_act` plus the **actor** token's `act`. It does not carry over the subject token's `act`, so the
  earlier hops would be lost.

Getting `user → s1 → s2 → s3 → s4` with a nested `act` chain needs the two customizations on branch
`claude/keycloak-rfc8693-poc`: a non-consent copy of the delegation scope, and a small token-exchange
provider. Otherwise, wait for Keycloak to support this natively.

## Layout

```
keycloak/setup_realm.py   realm, user, clients, scopes, FGAP permission (admin REST API, stdlib Python)
web-app/app.py            the web page: OIDC code flow + PKCE, server-side session, calls service-1
services/service.py       generic service: validate (introspection) -> token exchange -> call next
tests/e2e_browser.py      optional Playwright test of the whole browser flow
run-local.sh              no-Docker runner
docker-compose.yml        stock Keycloak image + setup + web-app + service-1..3
```

## Notes

* `token-exchange-delegation` and `parameterized-scopes` are **preview** features in 26.8 and may change.
* Token-exchange tokens are access tokens only, with no refresh token. They are valid only while alice's
  login session is alive.
* Services validate tokens by introspection, which returns `act` and `may_act`. Local JWT validation
  through JWKS works the same way: check `aud`, then read `sub` and `act`.
* Client secrets are `<client-id>-secret` and admin is admin/admin. Demo only.
