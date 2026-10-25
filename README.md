# RFC 8693 delegation chain on Keycloak 26.8.1 (POC)

```
alice ──► service-1 ──► service-2 ──► service-3 ──► service-4
```

At every hop the calling service exchanges the token it received for a new one meant only for the next
service (RFC 8693 token exchange). Every token keeps:

* `sub` = **alice**, the original user, never a service
* `act` = the **full delegation chain**, most recent actor first, with earlier actors nested (RFC 8693 §4.1)

The token that service-4 receives:

```json
{
  "sub": "<alice-id>", "preferred_username": "alice",
  "azp": "service-3",
  "aud": "service-4",
  "may_act": { "client_id": "service-4", "sub": "<service-4 service-account id>" },
  "act": {
    "client_id": "service-3", "sub": "...",
    "act": {
      "client_id": "service-2", "sub": "...",
      "act": { "client_id": "service-1", "sub": "..." }
    }
  }
}
```

service-4 reads this as `alice -> service-1 -> service-2 -> service-3 -> service-4`.

## Run it

**Docker:**

```bash
docker compose up -d --build                # Keycloak, realm setup, portal, service-1..4
docker compose logs -f keycloak-setup       # wait for "done."
```

**Without Docker** (needs Java 21, Maven, Python 3; downloads the Keycloak distribution):

```bash
./run-local.sh          # starts everything and runs the terminal demo
./run-local.sh stop
```

Admin console: http://localhost:8080/admin (admin/admin), realm `rfc8693`.

## Demo A — the browser journey

Open **http://localhost:8000** and sign in as `alice` / `alice`.

```
browser ──login──► Keycloak ──┐
   │  ◄── token (aud=service-1, may_act=service-1)
   │
   └─ click ─► service-1 ─► service-2 ─► service-3 ─► service-4
                                              (data comes back up the same way)
```

The portal is a plain static page (`ui/index.html`, no framework, no CDN). It does authorization
code + PKCE against `web-app`, asking for `scope=openid delegate-to:service-1`, then calls service-1
directly with the token it got back. One click starts the whole chain.

It shows three things an audience can follow:

1. **The token you came back with** — `sub` is alice, `aud` is service-1, `may_act` is service-1, and
   there is no `act` yet, because alice is calling service-1 herself.
2. **Behind the scenes** — one card per hop, showing that `sub` never stops being alice while `act`
   gains one more nested actor each time, and what `aud`/`may_act` each minted token carried.
3. **Can the chain be short-circuited?** — buttons that hand alice's token straight to service-3 or
   service-4, skipping the hops in between. Both come back `401 token not active`.
4. **Audit trail** — every request each service handled, with the delegation chain it saw and whether
   it allowed the call.

The attacks that need client secrets (exchanging a token meant for another service, replaying a token
already delegated away, minting a token for a service further down the chain) stay out of browser code
and live in `demo.py`.

The services label themselves Orders API / Billing / Payments / Ledger through `SERVICE_TITLE`; the
Keycloak client IDs are still `service-1`..`service-4`. service-4 returns the account data via
`SERVICE_DATA`.

## Demo B — under the hood

```bash
python3 demo.py                             # or: docker compose --profile demo run --rm demo
```

`demo.py` logs alice in, calls service-1, prints each hop's view of the token and runs 13 checks. 5 check
the happy path. The rest are negative checks:

| Check | Result |
|---|---|
| service-3 called directly with alice's service-1 token | `401 token not active` (introspection by service-3 reports `active: false`, because the token's `aud` is service-1) |
| service-3 tries to exchange a token whose `may_act` names service-2 | `400 Actor user is not allowed by the may_act claim` |
| service-1 tries to reuse the token it already delegated to service-2 | `400 Actor user is not allowed by the may_act claim` |
| service-1 tries to mint a token for service-3 or service-4 (skipping hops) | `400 Delegation from service-1 to service-3 is not an approved hop` |
| service-2 tries to mint a token for service-4 | `400 Delegation from service-2 to service-4 is not an approved hop` |
| service-4 called directly with alice's token | `401 token not active` |

## The approved call graph

The chain is `1 -> 2 -> 3 -> 4`, and only those hops are allowed. This is enforced twice, independently:

**At issuance, by Keycloak.** `DELEGATION_ALLOWED_HOPS` on the Keycloak container lists the approved
pairs; the `delegation-chain` provider refuses anything else, so service-1 cannot even *obtain* a token
for service-4:

```
DELEGATION_ALLOWED_HOPS=service-1>service-2,service-2>service-3,service-3>service-4
```

```
service-1 -> service-2   token issued
service-1 -> service-3   400 Delegation from service-1 to service-3 is not an approved hop
service-1 -> service-4   400 Delegation from service-1 to service-4 is not an approved hop
service-2 -> service-4   400 Delegation from service-2 to service-4 is not an approved hop
service-3 -> service-4   token issued
```

Each refusal is written to the Keycloak event log as a `TOKEN_EXCHANGE_ERROR` with
`error=delegation_hop_not_allowed` and `details.rejected_hop=service-1>service-4`.

**At the door, by the service.** Each service has `ALLOWED_CALLER` set to its approved predecessor and
checks the innermost `act.client_id` of the token it was handed, refusing anything else with a 403. This
is defense in depth: it still rejects a token minted before the rule existed, or one produced by a
future misconfiguration.

Note that this is *not* something `act` gives you for free. `act` is a truthful record of the
delegations that happened; it does not constrain them. Without the two rules above, Keycloak will
happily mint service-1 a token for service-4 and service-4 will accept it — the FGAP `delegate`
permission is a global "who may be delegated to" allowlist and cannot express a *pair*. See
`RFC8693-HANDOFF.md` §5.3 and §5.6.

## The audit picture

```bash
python3 audit.py              # both halves
python3 audit.py --issuance   # Keycloak's event log only
python3 audit.py --use        # what the services recorded only
```

Two independent records, deliberately kept separate:

1. **Issuance** — Keycloak's own event log. Every exchange is a `TOKEN_EXCHANGE` event carrying
   `details.actor` (who asked), `details.audience` (which service the token was minted for) and
   `details.username` (on whose behalf). Refusals are `TOKEN_EXCHANGE_ERROR`. Enabled on the realm by
   `setup_realm.py`.
2. **Use** — each service's `GET /audit`: who it saw, which chain delegated the call, and
   allow/deny with a reason. Every field is derived from the validated token, never from a header or
   anything the caller asserted.

```
1. ISSUANCE - Keycloak event log: who was given a token for what, on whose behalf
  time      event          actor        on behalf of  token minted for  outcome
  15:20:19  login          web-app      alice         -                 granted
  15:20:19  exchange       service-1    alice         service-2         granted
  15:20:19  exchange       service-2    alice         service-3         granted
  15:20:19  exchange       service-3    alice         service-4         granted
  15:20:19  exchange       service-1    alice         service-4         REFUSED  delegation_hop_not_allowed (service-1>service-4)

2. USE - what each service saw, and what it allowed or refused
  time      service                user    called by    delegation chain                     decision
  15:20:49  Orders API (service-1) alice   alice        -                                    allow
  15:20:49  Billing (service-2)    alice   service-1    service-1                            allow
  15:20:49  Payments (service-3)   alice   service-2    service-1 -> service-2               allow
  15:20:49  Ledger (service-4)     alice   service-3    service-1 -> service-2 -> service-3  allow
```

The portal shows the service-side half under **Audit trail**. Keycloak's event log needs admin
credentials, so it stays in `audit.py` rather than in browser code.

## How it works

### Keycloak features used (26.8.1)

| Piece | What it does |
|---|---|
| **Standard Token Exchange V2** (default on). Client attribute `standard.token.exchange.enabled=true` | Internal-to-internal RFC 8693 exchange |
| **`token-exchange-delegation`** (preview) + **`parameterized-scopes`** (preview) | Exchange with an `actor_token`. Keycloak checks the subject token's `may_act` against the actor and issues `act` |
| **Parameterized scope type `client-delegation`** | Requesting `delegate-to:<client>` adds `may_act={sub,client_id}` and `aud=<client>` to the issued token |
| **Fine-Grained Admin Permissions v2**: `delegate` permission on Users | Decides which clients may be named in `delegate-to:<client>`, i.e. who may act for users |
| **`delegation-chain` provider** (this repo, ~60 lines) | Nests the previous chain into `act` (see below) |

### One hop (service-N → service-N+1)

```
POST /realms/rfc8693/protocol/openid-connect/token
  grant_type         = urn:ietf:params:oauth:grant-type:token-exchange
  client_id/secret   = service-N
  subject_token      = <token service-N received>   (its may_act must name service-N)
  subject_token_type = urn:ietf:params:oauth:token-type:access_token
  actor_token        = <service-N's own client_credentials token>
  actor_token_type   = urn:ietf:params:oauth:token-type:access_token
  scope              = delegate-to:service-N+1
```

Keycloak checks the following:
1. The subject token is valid and addressed to service-N.
2. The actor token belongs to service-N.
3. The subject token's `may_act` names service-N.
4. service-N+1 holds the FGAP `delegate` permission.

It then issues a token with `sub=alice`, `aud=service-N+1`, `may_act=service-N+1`, and
`act={service-N, act:<previous chain>}`. See `services/service.py` for the client side (~20 lines).

The first hop is alice logging in to `web-app` with `scope=openid delegate-to:service-1`. Her token is
addressed to service-1 and allows service-1 to act for her. She calls service-1 directly, so this token
has no `act`.

### Why two things are custom

1. **`delegate-to` scope instead of the built-in `delegation:client` scope.** When the feature is on,
   Keycloak creates `delegation:client`, but marks it *always consent*. Consent can only be given in an
   interactive browser login, never during a token-exchange request. So the built-in scope only works for
   the first, user-facing hop. `setup_realm.py` clones it as `delegate-to`, with the same type and mappers
   but no always-consent, so services can use it for later hops. The FGAP `delegate` permission still
   controls who may be delegated to.
   *Production option:* keep `delegation:client` (with a consent screen) on the user-facing client, and use
   `delegate-to` only between services.

2. **`keycloak/delegation-chain-provider`.** The built-in delegation provider sets
   `act = may_act(subject_token)`, and only nests the `act` from the **actor** token. In a service chain
   the history is in the **subject** token, so it would be lost after one hop: service-4 would only see
   `act={service-3}`. The provider extends Keycloak's `TokenExchangeDelegationProvider` and changes only
   one thing: it appends the subject token's `act` as the innermost nested `act`. All validation is
   inherited. It is registered with a higher `order()` (20 vs 15), so Keycloak picks it for requests that
   carry an `actor_token`. Keycloak logs a warning at startup that this SPI is internal.

## Layout

```
keycloak/
  Dockerfile                       Keycloak 26.8.1 + features + provider
  setup_realm.py                   realm, user, clients, delegate-to scope, FGAP permission (admin REST API)
  delegation-chain-provider/       Java SPI: keeps the nested act chain
services/service.py                generic service (validate → enforce caller → exchange → call next); run 4 times
ui/index.html                      the portal: auth code + PKCE, one button, renders the whole chain
demo.py                            end-to-end demo + checks
audit.py                           consolidated audit: Keycloak issuance log + what each service recorded
run-local.sh                       no-Docker runner
docker-compose.yml
```

## Things to know / production notes

* **Preview features.** `token-exchange-delegation` and `parameterized-scopes` are preview in 26.8 and may
  change. The provider uses an internal SPI, so re-test it on every Keycloak upgrade (it is pinned to
  26.8.1 in `pom.xml` and the `Dockerfile`).
* **Restricting who can delegate to whom.** The POC grants `delegate` to all four services for all users.
  Make it stricter with per-client policies or per-user/group resources in FGAP. Also give each service
  only the `delegate-to` scope it needs: the scope is optional on every client here, so service-1 could
  technically request `delegate-to:service-4`.
* **Tokens from token exchange** are access tokens only — the response has no `refresh_token`, just
  `access_token`, `expires_in`, `issued_token_type` and `scope`.
* **Revoking the user does not revoke delegated tokens.** Each exchanged token gets its own transient
  session, which is *not* terminated with the user's. Measured: after `POST /logout` the original user
  token introspects `active: false`, while a token exchanged from it stays `active: true` — and still does
  after an admin `POST /users/{id}/logout` of every session that user has. A delegated token therefore
  lives until it expires (`accessTokenLifespan`, 1800s here). Keep that lifespan short if you need
  revocation to mean anything, and do not assume logout stops work already delegated downstream.
* **The portal keeps alice's token in the browser**, deliberately: the whole point of the demo is to put
  the real token on screen. In production, prefer a BFF — the server handles the callback, keeps the token
  in a session, and proxies the call to service-1 — so a delegation token never reaches the browser at all.
  `demo.py` still uses the password grant, purely so it stays scriptable; `ui/` uses authorization code +
  PKCE, which is what you would actually ship.
* **CORS, and why `webOrigins` is an explicit origin.** `web-app` lists `http://localhost:8000` rather than
  `"+"`. `"+"` means "derive the allowed origins from the redirect URIs", and Keycloak cannot derive one
  from the wildcard port in `http://localhost:*` — the preflight still succeeds, but the real `POST /token`
  is refused with `{"error":"Invalid origin"}`, which reaches the browser only as `TypeError: Failed to
  fetch`. Serving the portal from a different origin means adding it there (`PORTAL_ORIGIN` in
  `setup_realm.py`). The services themselves send `Access-Control-Allow-Origin: *`, which is safe here
  because they are bearer-authenticated and never read cookies.
* **The portal needs a secure context.** PKCE uses `crypto.subtle`, which browsers only expose over HTTPS
  or on localhost. Serving `ui/` from a LAN IP so other people can reach your laptop will break sign-in.
* **Validation in the services.** Services validate tokens by introspection, which preserves `act`. Local
  JWT validation through JWKS works too: check `aud` contains yourself, then read `sub` and `act`.
* **Secrets** are `<client-id>-secret`, and the admin login is admin/admin. Demo only.
