# Handoff: RFC 8693 agent delegation POC on Keycloak

Read this first when continuing the work in a new session.

## Goal

Agent identity ("Know Your Agent"): a user calls agent-1, which calls agent-2, which calls an MCP tool.
Every hop's token must say who the user is (`sub`) and the full path of agents (nested `act`, RFC 8693
§4.1), signed by Keycloak. In the demo code the agents are named `service-1` … `service-4`.

## Branches

| Branch | What | Status |
|---|---|---|
| `claude/keycloak-rfc8693-poc` | Option C: Keycloak 26.8.1 + `delegate-to` scope + `delegation-chain` provider (nests `act`). 4 services, `demo.py` | Tested, 8/8 |
| `claude/keycloak-rfc8693-native` | Stock Keycloak only, browser login page (`web-app/`), one delegated hop | Tested in a browser, 8/8 |
| `claude/gateway-kong-ai` (this one) | Option C + Kong Gateway doing every token exchange (`gateways/kong/`) | Tested with a Kong **stand-in** only, 13/13. **Real Kong not yet run** |

## Decisions made

- Recommendation is **option C** (config + the ~60-line provider jar). The provider extends Keycloak's
  `TokenExchangeDelegationProvider` via the SPI (not a fork); the SPI is internal, so rebuild and
  retest on every Keycloak upgrade.
- Keycloak features: `token-exchange-delegation`, `parameterized-scopes` (both preview in 26.8).
- Agent Gateway (agentgateway.dev) was evaluated and set aside for now.
- SPIFFE: **certificate-based** (X.509-SVIDs) for mTLS between agents and for agent → Keycloak login
  (`client-x509`, Subject DN `CN=<client_id>` set via the SPIRE entry's DNS name). Planned, not built.
  Do not enable RFC 8705 cert-bound tokens for agents: Keycloak then refuses the next hop's exchange.
- Kong: each route authenticates to Keycloak **as the calling agent** (Keycloak requires the requester
  to be the `may_act` client and the actor token's owner). Agents attach their own actor token in
  `X-Actor-Token`; Kong does not mint it.

## Next step on this branch

Run against real Kong Gateway Enterprise (needs a licence and Docker):

```bash
export KONG_LICENSE_DATA="$(cat /path/to/license.json)"
docker compose -f docker-compose.yml -f docker-compose.kong.yml up -d --build
docker compose logs -f keycloak-setup      # wait for "done."
KONG_URL=http://localhost:8000 python3 demo.py
```

Expect to fix: field names Kong rejects in `gateways/kong/kong.yaml`, extra parameters Kong sends in
the exchange that Keycloak refuses, Kong's error status codes. Also confirm Kong's exchange cache can't
bypass the actor check (`cache_tokens: false` is set) and that a tampered token is rejected at Kong.
See "Not yet verified on real Kong" in `gateways/kong/README.md`.

Without Docker/licence: `./run-local.sh kong-standin` (stand-in) or `./run-local.sh` (no gateway).

## Later

- MCP tool behind Kong's AI MCP Proxy + AI MCP OAuth2 with per-agent tool ACLs.
- One branch combining the browser login page, the full chain to an MCP tool, and SPIFFE mTLS.
- Update the deck (https://claude.ai/artifact/EP27GZBecc6nVT5NwJe5ew) for Kong and SPIFFE.
