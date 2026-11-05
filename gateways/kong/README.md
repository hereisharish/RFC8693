# Kong Gateway between the services: Kong does every Keycloak call

Keycloak (with the `delegation-chain` plugin) still issues every token and builds the nested `act`
chain. Kong sits between the services: it performs each RFC 8693 token exchange, checks the new
token's audience, and proxies the services' remaining Keycloak calls. No service talks to Keycloak
directly.

```
alice ─login─► Keycloak                          (demo.py: password grant, as on the base branch)
alice ─T0─► service-1 ─► Kong /service-1/to/service-2 ─T1─► service-2 ─► Kong /service-2/to/service-3 ─T2─► …
                          │ exchange as service-1                      │ exchange as service-2
                          ▼                                            ▼
                    Keycloak token endpoint (subject_token + actor_token + scope delegate-to:<target>)
services ─► Kong /idp ─► Keycloak   (actor tokens via client_credentials, introspection)
```

## Files

| File | What |
|---|---|
| [`kong.yaml`](kong.yaml) | Kong declarative config (DB-less): one route per caller → callee hop, plus `/idp` |
| [`../../docker-compose.kong.yml`](../../docker-compose.kong.yml) | Overlay adding Kong Gateway Enterprise 3.16.0.1 and pointing the services at it |
| [`standin.py`](standin.py) | Local stand-in that reads `kong.yaml` and mimics the documented plugin behaviour, for testing without a licence |
| `services/service.py` | `EXCHANGE_VIA=gateway`: no exchange in the service; sends its token plus `X-Actor-Token` to the next Kong route |
| `demo.py` | With `KONG_URL` set, adds five gateway checks |

## One hop, e.g. route `/service-1/to/service-2`

1. service-1 receives alice's token T0 (`aud=service-1`, `may_act=service-1`).
2. service-1 gets its own actor token (`client_credentials` through `/idp`) and calls the route
   with `Authorization: Bearer T0` and `X-Actor-Token: <actor token>`.
3. The `openid-connect` plugin:
   - accepts tokens from the realm issuer, verifying the subject token's signature
     (`verify_signature: true`);
   - exchanges only when the token is addressed to the caller (`conditions.has_audience: [service-1]`);
   - calls Keycloak's token endpoint **as service-1** (`client_id`/`client_secret` on this route) with
     the actor token from `X-Actor-Token` and `scope=delegate-to:service-2`;
   - requires the token it forwards to carry `aud=service-2` (`audience_required`).
4. `request-transformer` removes `X-Actor-Token`, so service-2 never sees service-1's actor token.
5. service-2 receives T1 (`sub=alice`, `act={service-1}`, `aud=service-2`) and validates it.

## Why each route has its own client credentials

Keycloak's delegation check requires the client making the exchange request to be the agent named
in the subject token's `may_act`, which is also the actor token's owner. So Kong must call Keycloak as
the acting service, not as one shared "kong" client. In `kong.yaml` each route carries its caller's
credentials (the POC's `<client-id>-secret` values; use Kong vault references in a real deployment).

## Run it

**With Kong** (needs a Kong Enterprise or Konnect trial licence; the `openid-connect` plugin is
Enterprise, actor tokens need 3.16+):

```bash
export KONG_LICENSE_DATA="$(cat license.json)"
docker compose -f docker-compose.yml -f docker-compose.kong.yml up -d --build
docker compose logs -f keycloak-setup      # wait for "done."
KONG_URL=http://localhost:8000 python3 demo.py
```

**With the stand-in** (no Docker or licence; Java 21, Maven, Python 3 + PyYAML):

```bash
./run-local.sh kong-standin     # Keycloak, realm, stand-in on :8000, services in gateway mode, demo
./run-local.sh stop
```

Keycloak must run with `KC_HOSTNAME=http://localhost:8080` so tokens keep the same issuer when the
services reach Keycloak through the gateway.

## Tested

Against Keycloak 26.8.1 with the stand-in (not real Kong): **13/13 checks pass**. These include the
gateway checks:

| Check | Result |
|---|---|
| Every hop's exchange done by the gateway; full `act` chain reaches service-4 | pass |
| No service receives `X-Actor-Token` | pass |
| service-3's actor token on service-1's route | 401, Keycloak: "Client is not within the token audience" |
| Token addressed to service-1 sent to service-2's route | 403, no exchange and `audience_required` fails |
| No actor token | 401, Keycloak: "Subject token with a delegation claim is not allowed for standard token exchange" |

## Not yet verified on real Kong

- Kong's exact behaviour and status codes when the exchange fails (the stand-in returns 401).
- Whether Kong sends any parameters beyond the ones above (e.g. `requested_token_type`, an empty
  `audience`) and whether Keycloak accepts them.
- Kong's exchange cache: `cache_tokens: false` is set so a cached result can't skip Keycloak's actor
  check; confirm what Kong keys its exchange cache on before enabling caching.
- `kong.yaml` was written from Kong's docs (github.com/Kong/developer.konghq.com), not validated by
  Kong itself: run `deck gateway validate` or start Kong with it first.

## Not included (next steps)

- The MCP tool behind Kong's AI MCP Proxy + AI MCP OAuth2 plugins with per-agent tool ACLs
  (`consumer_claim: [act, client_id]`). AI MCP OAuth2's token exchange is tech preview in 3.14+.
- The browser login web page (on `claude/keycloak-rfc8693-native`).
