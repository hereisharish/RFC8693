# Kong AI Gateway with the RFC 8693 delegation chain

Status: **design notes, not yet built or run.** Based on Kong's docs
(github.com/Kong/developer.konghq.com) and the Keycloak 26.8.1 source.

## Where Kong fits

Kong does not issue tokens. Keycloak (with the `delegation-chain` plugin on this branch) stays the
authorization server that issues every token and builds the nested `act` chain. Kong sits in front of
agents and MCP tools and does three jobs:

| Job | Kong plugin | Tier / version |
|---|---|---|
| Validate the incoming token (issuer, signature, expiry, audience) | OpenID Connect, or AI MCP OAuth2 for MCP servers | Enterprise; AI MCP OAuth2 is AI Gateway Enterprise, 3.12+ |
| RFC 8693 exchange before forwarding to the next hop | OpenID Connect `config.token_exchange` (3.14+, actor token 3.16+) or AI MCP OAuth2 `config.token_exchange` (3.14+, **tech preview**) | Enterprise |
| Per-tool authorization on MCP traffic | AI MCP OAuth2 `consumer_claim` → Kong Consumer, then AI MCP Proxy tool ACLs | AI Gateway Enterprise, 3.13+ |

The OpenID Connect and AI MCP plugins are not in open-source Kong: a POC needs an Enterprise or
Konnect trial licence.

## Target flow

```
alice → web app → agent-1 → [Kong route A1→A2] → agent-2 → [Kong route A2→MCP] → mcp-tool
                                 │ token exchange           │ token exchange + tool ACL
                                 └────────── Keycloak 26.8.1 + delegation-chain plugin ──┘
```

On the route in front of the next hop, Kong:
1. validates the incoming token (`verify_signature: true` on the subject token issuer);
2. calls Keycloak's token endpoint with `grant_type=token-exchange`, the incoming token as
   `subject_token`, the actor token from the `X-Actor-Token` header, and
   `scope=delegate-to:<next hop>`;
3. forwards the new token (`sub=alice`, `act` = full chain, `aud=<next hop>`) upstream.

## Constraints

1. **Kong must authenticate to Keycloak as the acting agent, not as "kong".** Keycloak's delegation
   check requires the requesting client to equal the `client_id` in the subject token's `may_act`
   and the actor token's `azp`. So each caller → callee route carries that caller's own client
   credentials (`client_id`/`client_secret` on the plugin instance). One shared Kong client
   identity would be refused.
2. **Kong does not mint the actor token.** Both plugins read it from a request header (or a static
   value, which would expire). The calling agent still fetches its own `client_credentials`
   token and sends it as `X-Actor-Token`.
3. **Exchange conditions.** When subject and target issuer are the same (one Keycloak realm), Kong
   only exchanges when the configured `conditions` match, e.g. `has_audience: [agent-2]`.
4. **Tool ACLs are per Consumer.** Mapping `consumer_claim: [act, client_id]` makes the immediate
   caller the Consumer, so ACLs can say "agent-2 may call `list_orders`". Rules on the whole
   chain (`act.act.client_id`) are not expressible with the built-in ACLs; the chain can be
   forwarded to the MCP server with `upstream_headers`, or checked by custom code.
5. **AI MCP OAuth2 token exchange is tech preview** in 3.14.

## OpenID Connect plugin sketch (route agent-1 → agent-2)

```yaml
plugins:
- name: openid-connect
  route: agent-1-to-agent-2
  config:
    issuer: http://keycloak:8080/realms/rfc8693
    client_id: [service-1]              # the ACTING agent's Keycloak client
    client_secret: [service-1-secret]
    client_auth: [client_secret_post]
    auth_methods: [bearer]
    token_exchange:
      subject_token_issuers:
      - issuer: http://keycloak:8080/realms/rfc8693
        verify_signature: true
        conditions:
          has_audience: [service-2]     # assumed: exchange tokens addressed to agent-2
      request:
        scopes: [delegate-to:service-2]  # assumed: gives the new token may_act=service-2
        actor_token:
          source: header
          header_name: X-Actor-Token
          type: urn:ietf:params:oauth:token-type:access_token
```

The assumed `conditions` and `scopes` semantics need verifying against Kong's reference
docs in the POC.

## POC plan

1. Kong Gateway Enterprise 3.16 (trial licence) in docker-compose, DB-less, config via decK.
2. Move the exchange out of `services/service.py` into Kong routes; agents only attach
   `X-Actor-Token`.
3. MCP tool behind AI MCP Proxy + AI MCP OAuth2 with tool ACLs on `act.client_id`.
4. Tests: full chain still reaches the MCP tool; a wrong caller on a route is refused; a token
   not addressed to the route is not exchanged; a tool ACL denies an agent it doesn't list.
