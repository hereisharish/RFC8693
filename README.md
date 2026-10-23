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
docker compose up -d --build                # Keycloak, realm setup, service-1..4
docker compose logs -f keycloak-setup       # wait for "done."
python3 demo.py                             # or: docker compose --profile demo run --rm demo
```

**Without Docker** (needs Java 21, Maven, Python 3; downloads the Keycloak distribution):

```bash
./run-local.sh          # starts everything and runs the demo
./run-local.sh stop
```

`demo.py` logs alice in, calls service-1, prints each hop's view of the token and runs 8 checks. 5 check
the happy path. 3 are negative checks:

| Check | Result |
|---|---|
| service-3 called directly with alice's service-1 token | rejected (token isn't addressed to service-3) |
| service-3 tries to exchange a token whose `may_act` names service-2 | `400 Actor user is not allowed by the may_act claim` |
| service-1 tries to reuse the token it already delegated to service-2 | `400 Actor user is not allowed by the may_act claim` |

Admin console: http://localhost:8080/admin (admin/admin), realm `rfc8693`.

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
services/service.py                generic service (validate → exchange → call next); run 4 times
demo.py                            end-to-end demo + checks
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
* **Tokens from token exchange** are access tokens only (no refresh token), backed by a transient session.
  The chain is valid only while alice's original SSO session is alive.
* **`web-app` uses the password grant** only to keep the demo scriptable. Use authorization code + PKCE in
  real life.
* **Validation in the services.** Services validate tokens by introspection, which preserves `act`. Local
  JWT validation through JWKS works too: check `aud` contains yourself, then read `sub` and `act`.
* **Secrets** are `<client-id>-secret`, and the admin login is admin/admin. Demo only.
