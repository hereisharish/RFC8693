# RFC 8693 delegation on Keycloak — verified working reference, and how to port it to an agent system

**Purpose.** This is a self-contained handoff. Everything needed is inline — versions, full config
payloads, full Java source, exact request shapes, exact error strings. You do not need internet access,
and you should not need to consult Keycloak documentation to act on this.

**Status.** Every claim marked *measured* was executed against a running Keycloak **26.8.1** and the
observed output is quoted. Claims not marked *measured* are design guidance for your system and are
labelled as such. Where something is untested for your architecture, this document says so rather
than guessing.

**What the reference system does.** A user (alice) opens a browser page, logs in, clicks a button. One
request goes to service-1, which calls service-2 → service-3 → service-4. Every token in that chain keeps
`sub` = alice and carries a nested `act` claim recording the full delegation path. The last service knows
both *who the human is* and *which services the request passed through*, cryptographically, with no
forgeable headers.

---

## 1. The model: four claims

| Claim | Meaning | In the reference chain |
|---|---|---|
| `sub` | Who the request is *about*. Never changes. | always alice's user id |
| `act` | Who is *acting*, most recent actor first, earlier actors nested inside | `{client_id: service-3, act: {client_id: service-2, act: {client_id: service-1}}}` |
| `aud` | Who this token may be presented to | the next service, and only that one |
| `may_act` | Who is allowed to exchange this token to act for `sub` | the next service, and only that one |

The pairing of `aud` + `may_act` is what makes the chain safe: a token addressed to service-2 can only be
*used* at service-2 and only *exchanged* by service-2.

`act` is an **audit record of delegations that actually happened**. It is not an enforced topology — see
§5.3, which is a measured result and a common source of false assumptions.

---

## 2. The exchange request (the core operation)

One hop, service-N delegating to service-N+1:

```
POST /realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type         = urn:ietf:params:oauth:grant-type:token-exchange
client_id          = service-N
client_secret      = <service-N secret>
subject_token      = <the token service-N received>
subject_token_type = urn:ietf:params:oauth:token-type:access_token
actor_token        = <service-N's own client_credentials token>
actor_token_type   = urn:ietf:params:oauth:token-type:access_token
scope              = delegate-to:service-N+1
```

Keycloak checks, in this order:

1. the subject token is valid and its `aud` includes service-N;
2. the `actor_token` really belongs to service-N (this is what stops impersonation);
3. the subject token's `may_act` names service-N;
4. the client named in `delegate-to:<client>` holds the FGAP `delegate` permission on Users.

Response (*measured* — exact key set):

```json
{ "access_token": "...", "expires_in": 1800, "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "scope": "...", "refresh_expires_in": 0, "not-before-policy": 0 }
```

**There is no `refresh_token`.** *(measured)* Plan for that — see §5.4.

The issued token has `sub` = the user, `aud` = the delegated-to client, `may_act` = the delegated-to
client, and `act` = service-N wrapped around the subject token's previous `act`.

---

## 3. The Keycloak setup, in full

### 3.1 Version and features

Keycloak **26.8.1**, started with:

```
KC_FEATURES=token-exchange-delegation,parameterized-scopes
```

Both are **preview** features in 26.8 and may change between versions. Standard Token Exchange V2 is on
by default; each participating client additionally needs the attribute
`standard.token.exchange.enabled = "true"`.

### 3.2 Realm

```json
{ "realm": "rfc8693", "enabled": true,
  "adminPermissionsEnabled": true,
  "accessTokenLifespan": 1800 }
```

`adminPermissionsEnabled` turns on **Fine-Grained Admin Permissions v2**, which is required for the
`delegate` permission in §3.5. Without it the exchange fails at step 4.

### 3.3 Clients

The front end — public, authorization code + PKCE:

```json
{ "clientId": "web-app", "publicClient": true, "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["http://localhost:*"],
  "webOrigins": ["http://localhost:8000"],
  "fullScopeAllowed": false,
  "attributes": { "post.logout.redirect.uris": "+" } }
```

`webOrigins` **must be an explicit origin, not `"+"`** — see §6.1, this cost real debugging time.

Each participating service — confidential, with a service account:

```json
{ "clientId": "service-N", "publicClient": false, "secret": "<secret>",
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
  "fullScopeAllowed": false,
  "attributes": { "standard.token.exchange.enabled": "true" } }
```

`serviceAccountsEnabled` is required: the service needs its own `client_credentials` token to send as
`actor_token`.

### 3.4 The parameterized scope — the central trick

When `token-exchange-delegation` is enabled, Keycloak creates a built-in scope `delegation:client`.
**It is unusable for service-to-service hops**, because it carries:

```json
"display.on.consent.screen": "true",
"always.display.consent": "true"
```

Consent can only be granted in an interactive browser login, and there is no browser inside a token
exchange request. So the built-in scope works only for the first, user-facing hop.

The fix is to clone it without the consent attributes. Create this client scope:

```json
{ "name": "delegate-to", "protocol": "openid-connect",
  "attributes": {
    "is.parameterized.scope": "true",
    "parameterized.scope.type": "client-delegation",
    "include.in.token.scope": "true",
    "display.on.consent.screen": "false" } }
```

with exactly these three protocol mappers (*measured* — copied from a working realm):

```json
[
  { "name": "client may_act sub",
    "protocolMapper": "oidc-parameterized-scope-client-sub-mapper",
    "consentRequired": false,
    "config": { "claim.name": "may_act.sub", "jsonType.label": "String",
                "access.token.claim": "true", "id.token.claim": "true",
                "introspection.token.claim": "true", "userinfo.token.claim": "true" } },

  { "name": "client may_act client_id",
    "protocolMapper": "oidc-parameterized-scope-mapper",
    "consentRequired": false,
    "config": { "claim.name": "may_act.client_id", "jsonType.label": "String",
                "access.token.claim": "true", "id.token.claim": "true",
                "introspection.token.claim": "true", "userinfo.token.claim": "true" } },

  { "name": "client delegation audience",
    "protocolMapper": "oidc-parameterized-scope-audience-mapper",
    "consentRequired": false,
    "config": { "access.token.claim": "true", "introspection.token.claim": "true" } }
]
```

Assign `delegate-to` as an **optional** client scope to every client that must either request delegation
or be delegated to.

Requesting `scope=delegate-to:<client-id>` then puts `may_act={sub, client_id}` and `aud=<client-id>` into
the issued token. The `<client-id>` after the colon is the scope *parameter* — that is what
"parameterized scope" means, and it is why the `parameterized-scopes` feature flag is required.

*Production note:* you can keep `delegation:client` (with its consent screen) on the user-facing client,
and use `delegate-to` only between back-end services.

### 3.5 The FGAP `delegate` permission

This is what decides *which clients may be named* in `delegate-to:<client>`. Created against the realm's
built-in `admin-permissions` client:

```
POST /admin/realms/{realm}/clients/{admin-permissions-id}/authz/resource-server/policy/client
{ "name": "delegating-services", "logic": "POSITIVE",
  "clients": ["<internal id of service-1>", ... ] }

POST /admin/realms/{realm}/clients/{admin-permissions-id}/authz/resource-server/permission/scope
{ "name": "services-may-delegate-for-all-users", "resourceType": "Users",
  "scopes": ["delegate"], "policies": ["<id of the policy above>"],
  "decisionStrategy": "UNANIMOUS" }
```

The reference grants `delegate` on **all** users to **all** four services, which is deliberately loose for
a POC. Narrow it with per-client policies or per-user/group resources.

### 3.6 The custom provider — and exactly why it is needed

**The problem.** Keycloak's built-in delegation provider sets `act = may_act(subject_token)` and nests only
the `act` found on the **actor** token. In a service chain the history lives in the **subject** token. So
without this provider the chain is lost after one hop: service-4 would see only `act = {service-3}`,
with no record that service-1 and service-2 were ever involved.

**The fix.** Extend the built-in provider and append the subject token's `act` as the innermost nested
`act`. All validation is inherited unchanged. Complete source:

`src/main/java/poc/keycloak/delegation/DelegationChainTokenExchangeProvider.java`

```java
package poc.keycloak.delegation;

import java.util.LinkedHashMap;
import java.util.Map;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.tokenexchange.TokenExchangeDelegationProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

public class DelegationChainTokenExchangeProvider extends TokenExchangeDelegationProvider {

    @Override
    protected void checkRequestedAudiences(TokenManager.AccessTokenResponseBuilder responseBuilder) {
        super.checkRequestedAudiences(responseBuilder);

        Map<String, Object> claims = responseBuilder.getAccessToken().getOtherClaims();
        Object act = claims.get(IDToken.ACT);
        Object priorChain = subjectTokenAct();
        if (!(act instanceof Map<?, ?> actMap) || !(priorChain instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> chain = copy(actMap);
        Map<String, Object> innermost = chain;
        while (innermost.get(IDToken.ACT) instanceof Map<?, ?> next) {
            Map<String, Object> nextCopy = copy(next);
            innermost.put(IDToken.ACT, nextCopy);
            innermost = nextCopy;
        }
        innermost.put(IDToken.ACT, priorChain);
        claims.put(IDToken.ACT, chain);
    }

    // The subject_token has already been verified (signature, expiry, session) by the parent class.
    private Object subjectTokenAct() {
        try {
            AccessToken subjectToken = new JWSInput(params.getSubjectToken()).readJsonContent(AccessToken.class);
            return subjectToken.getOtherClaims().get(IDToken.ACT);
        } catch (JWSInputException e) {
            return null;
        }
    }

    private static Map<String, Object> copy(Map<?, ?> source) {
        Map<String, Object> target = new LinkedHashMap<>();
        source.forEach((k, v) -> target.put(String.valueOf(k), v));
        return target;
    }
}
```

`src/main/java/poc/keycloak/delegation/DelegationChainTokenExchangeProviderFactory.java`

```java
package poc.keycloak.delegation;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public class DelegationChainTokenExchangeProviderFactory
        implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {

    public static final String ID = "delegation-chain";

    @Override public TokenExchangeProvider create(KeycloakSession session) {
        return new DelegationChainTokenExchangeProvider();
    }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    @Override public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE_DELEGATION);
    }

    @Override public int order() {
        // built-in "delegation" is 15, "standard" is 10: requests with an actor_token come here first
        return 20;
    }
}
```

`src/main/resources/META-INF/services/org.keycloak.protocol.oidc.TokenExchangeProviderFactory`

```
poc.keycloak.delegation.DelegationChainTokenExchangeProviderFactory
```

`pom.xml` — both dependencies are `provided`:

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>poc.keycloak</groupId>
  <artifactId>delegation-chain-provider</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <properties>
    <keycloak.version>26.8.1</keycloak.version>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.keycloak</groupId><artifactId>keycloak-services</artifactId>
      <version>${keycloak.version}</version><scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.keycloak</groupId><artifactId>keycloak-server-spi-private</artifactId>
      <version>${keycloak.version}</version><scope>provided</scope>
    </dependency>
  </dependencies>
  <build><finalName>${project.artifactId}</finalName></build>
</project>
```

Dockerfile:

```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS provider
WORKDIR /build
COPY delegation-chain-provider/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY delegation-chain-provider/src ./src
RUN mvn -q -B package

FROM quay.io/keycloak/keycloak:26.8.1 AS builder
ENV KC_FEATURES=token-exchange-delegation,parameterized-scopes
COPY --from=provider /build/target/delegation-chain-provider.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.1
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENV KC_FEATURES=token-exchange-delegation,parameterized-scopes
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

**Warning.** `TokenExchangeDelegationProvider` is an internal Keycloak SPI. Keycloak logs a warning about
this at startup. It is pinned to 26.8.1 in both the pom and the Dockerfile. **Re-test on every Keycloak
upgrade** — this class can change without notice.

### 3.7 Validating tokens in a service

Introspection is used in the reference because it preserves `act`:

```
POST /realms/{realm}/protocol/openid-connect/token/introspect
token=<token>&client_id=<me>&client_secret=<my secret>
```

Then check `active == true` **and** that `aud` contains your own client id. Local JWT validation via JWKS
works equally well; just perform the same two checks.

---

## 4. Verified behaviours (all *measured*)

### 4.1 The happy path

Token received by service-4:

```json
{ "sub": "<alice>", "preferred_username": "alice",
  "azp": "service-3", "aud": "service-4",
  "may_act": { "client_id": "service-4", "sub": "<service-4 service account>" },
  "act": { "client_id": "service-3",
           "act": { "client_id": "service-2",
                    "act": { "client_id": "service-1" } } } }
```

### 4.2 Rejections, with exact error strings

| Attack | Result |
|---|---|
| Present alice's service-1 token directly to service-3 | `401`, introspection returns `active: false` — **not** a 403. Introspection reports inactive when the introspecting client is not in `aud`, so an audience check in your own code never even runs. |
| service-3 tries to exchange a token whose `may_act` names service-2 | `400 {"error":"invalid_request","error_description":"Actor user is not allowed by the may_act claim inside the subject_token"}` |
| service-1 replays a token it already delegated to service-2 | same `400`, same message |

### 4.3 Interactive login carries the delegation claims

Authorization code + PKCE with `scope=openid delegate-to:service-1` yields `aud: service-1` and
`may_act.client_id: service-1`. The parameterized scope is **not** limited to the password grant.

### 4.4 Refreshing the *user's* token preserves delegation

`grant_type=refresh_token` on the user's session returns an access token that still has
`aud: service-1`, `may_act: service-1`, and the same `scope`. Safe to refresh silently.

---

## 5. Eight behaviours that will shape your design (all *measured*)

These are the results most likely to invalidate assumptions. Read them before designing.

### 5.1 Fan-out works — one token, many targets

The same subject token can be exchanged repeatedly for **different** targets:

```
service-1 exchanges alice's token -> service-2  OK (aud=service-2, act=service-1)
service-1 exchanges alice's token -> service-3  OK (aud=service-3, act=service-1)
service-1 exchanges alice's token -> service-4  OK (aud=service-4, act=service-1)
```

This is the single most important result for an agent architecture: **an orchestrator calling N tools is
directly supported.** You do not need a linear chain.

### 5.2 Subject tokens are not consumed

Exchanging the same subject token twice for the same target returns two valid tokens. Agent loops that
call the same tool repeatedly are fine; you may also cache per-target tokens for their lifetime rather
than exchanging on every call.

### 5.3 `act` is an audit trail, not an enforced route

service-1 can mint a token addressed straight to service-4, skipping 2 and 3, and **service-4 accepts it
(HTTP 200)**. The resulting `act` is simply `{client_id: service-1}`.

So `act` tells you *what actually happened*, truthfully and unforgeably. It does **not** prove a request
followed a prescribed path. If you need "only the orchestrator may call tool X", enforce that with FGAP
policies and per-client scope assignment — **not** by inspecting `act`. A service that wants to require
a particular caller must check `act.client_id` itself, explicitly.

### 5.4 Exchanged tokens carry no refresh token

The response has no `refresh_token` (§2). A delegated token simply expires. Long-running work must
either re-exchange from a still-valid subject token, or hold the *user's* refresh token upstream and mint
a fresh subject token first.

### 5.5 The FGAP `delegate` permission is a *target* allowlist, and fails silently

Measured, and worth knowing before you design per-tool authorisation: the client policy attached to the
`delegate` permission lists **who may be delegated to**, not who may ask.

With the policy containing only `service-1`:

```
user logs in asking delegate-to:service-1  ->  aud=service-1, may_act=service-1   (service-1 is listed)
user logs in asking delegate-to:service-2  ->  aud=null, may_act=null             (service-2 is not)
service-1 exchanges for delegate-to:service-2 -> HTTP 200, but aud=null, may_act=null,
                                                 and "delegate-to:service-2" is dropped from scope
```

Two consequences:

- **It cannot express a pair.** "service-3 may delegate to service-4 but service-1 may not" is
  inexpressible, because the permission only knows about service-4 as a target. For per-pair rules you
  need something else — §5.6.
- **Denial is silent.** The exchange returns **HTTP 200** with a token that merely has no `aud` and no
  `may_act`, and the requested scope quietly missing from the `scope` response field. Nothing says
  "denied". The next hop then fails with the confusing
  `Invalid may_act claim in the subject_token`, pointing at the wrong place entirely. If a delegation
  is mysteriously not working, **check whether the target holds the FGAP `delegate` permission** before
  anything else, and assert on `may_act` being present rather than on the HTTP status.

### 5.6 Enforcing an approved call graph (what this repo does)

Since `act` only records (§5.3) and FGAP only gates targets (§5.5), enforcing "only service-N may
delegate to service-N+1" needs explicit work. This repo does it in two independent layers:

**Issuance.** `DelegationChainTokenExchangeProvider` reads the delegation target and refuses
unapproved pairs. The approved graph comes from an env var:

```
DELEGATION_ALLOWED_HOPS=service-1>service-2,service-2>service-3,service-3>service-4
```

```java
// inside checkRequestedAudiences, AFTER super.checkRequestedAudiences(responseBuilder)
if (!(claims.get("may_act") instanceof Map<?, ?> mayAct)) return;   // not a delegation request
String targetId = String.valueOf(mayAct.get("client_id"));
String actor = client.getClientId();
if (!allowedHops.getOrDefault(actor, Set.of()).contains(targetId)) {
    event.detail("rejected_hop", actor + ">" + targetId);
    event.error("delegation_hop_not_allowed");        // without this the refusal is NOT audited
    throw new CorsErrorResponseException(cors, "invalid_request",
        "Delegation from " + actor + " to " + targetId + " is not an approved hop",
        Response.Status.BAD_REQUEST);
}
```

Two traps found the hard way:

- **Read the target from `may_act`, not from `getTargetAudienceClients()`.** The latter returns the
  RFC 8693 `audience` *request parameter*, which defaults to the calling client itself when absent —
  so every hop evaluates as "service-1 -> service-1" and the whole chain breaks. The delegation target
  is whoever `may_act` names, which means the check must run **after** `super`, once the claim exists.
- **Call `event.error(...)` before throwing.** Throwing alone rejects the request but writes **no**
  `TOKEN_EXCHANGE_ERROR` event — the blocked attempt leaves no audit trace at all.

**At the resource.** Each service also checks the innermost `act.client_id` of the token presented to
it against its one approved predecessor, and returns 403 otherwise. Cheap, and it still catches tokens
minted before a rule existed or produced by a misconfiguration.

Result (measured): `service-1 -> service-3`, `service-1 -> service-4` and `service-2 -> service-4` are
all refused at issuance with `400 ... is not an approved hop`, while the approved hops still work.

### 5.7 What the audit log actually contains

Realm config `eventsEnabled: true` (plus `eventsListeners: ["jboss-logging"]`) turns this on. Every
exchange then produces a `TOKEN_EXCHANGE` event whose `details` carry exactly the delegation question:

```json
{ "type": "TOKEN_EXCHANGE", "clientId": "service-1", "userId": "...",
  "details": { "actor": "service-1", "actor_id": "...", "actor_type": "client",
               "audience": "service-2", "username": "alice",
               "subject_token_client_id": "web-app",
               "scope": "delegate-to:service-2 profile email",
               "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange" } }
```

`actor` = who asked, `audience` = which service the token was minted for, `username` = on whose behalf.
Refusals arrive as `TOKEN_EXCHANGE_ERROR` with an `error` field. Read them from
`GET /admin/realms/{realm}/events?type=TOKEN_EXCHANGE` with an admin token.

For an agent system this is the record that answers "which agent obtained access to which tool, for
which user, and when" — without trusting anything the agent reported about itself. Pair it with a
resource-side log (what each tool actually saw in the token it validated) and you have both halves.

### 5.8 Revoking the user does **not** revoke delegated tokens

This is the sharpest finding, and it contradicts a natural assumption.

```
user sessions before logout: 3
delegated token BEFORE logout:            {"active": true,  "act": "service-1"}
POST /logout  (the user's own session)
user sessions after logout:  2
ORIGINAL user token AFTER logout:         {"active": false}
delegated token AFTER logout:             {"active": true,  "act": "service-1"}
delegated token AFTER admin logout-all:   {"active": true,  "act": "service-1"}
```

Each exchanged token gets its **own transient session**, which is not terminated with the user's — not by
user logout, and not by an admin logging out every session that user has. The delegated token stays valid
until `accessTokenLifespan` elapses.

Consequences for an agent system:

- *Helpful:* a background agent keeps working after the user closes the tab.
- *Dangerous:* "revoke the user" does not stop in-flight delegated work. If revocation must bite, keep
  `accessTokenLifespan` short (the reference uses 1800s purely so live demos do not expire mid-talk —
  that is far too long for production) and add your own revocation check at the tool boundary.

---

## 6. Failure modes and how to recognise them

Each of these was hit and diagnosed during the build.

### 6.1 `TypeError: Failed to fetch` in the browser

Keycloak returned **`403 {"error":"Invalid origin"}`** on `POST /token`.

Cause: the client had `webOrigins: ["+"]`. `"+"` means *derive the allowed CORS origins from the redirect
URIs*, and Keycloak **cannot derive a concrete origin from a wildcard port** such as
`http://localhost:*`. The cruel part: the **preflight still succeeds** and returns a correct
`Access-Control-Allow-Origin` header, so an `OPTIONS` probe with curl looks perfectly healthy. Only the
real request is refused, and the browser surfaces it as an opaque `Failed to fetch`.

Fix: list the explicit origin, e.g. `webOrigins: ["http://localhost:8000"]`.

Diagnose it with the **actual** request, never a preflight:

```bash
curl -s -i -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -H 'Origin: http://your-app-origin' \
  -d grant_type=authorization_code -d client_id=web-app -d code=bogus
# "Invalid origin" (403) = CORS problem.  "Code not valid" (400) = CORS is fine.
```

### 6.2 Consent error, or `may_act` missing after a service-to-service exchange

You are using the built-in `delegation:client` scope. It is `always.display.consent`, which cannot be
satisfied without a browser. Clone it as `delegate-to` per §3.4.

### 6.3 `act` only ever one level deep

The custom provider is not loaded. Check that the jar is in `/opt/keycloak/providers/`, that `kc.sh build`
ran after it was copied, that the `META-INF/services` file is present in the jar, and that `order()`
returns a value above the built-in `15`.

### 6.4 Exchange fails at the permission step

FGAP is off (`adminPermissionsEnabled: true` missing on the realm) or the delegated-to client is not in
the `delegating-services` policy.

### 6.5 Browser login silently broken

`crypto.subtle` — required for the PKCE S256 challenge — is only available in a **secure context**:
HTTPS, or `localhost`. Serving the front end from a LAN IP so colleagues can reach it will break sign-in.

### 6.6 Everything 401s shortly after it starts working

`accessTokenLifespan` elapsed. Tokens are not auto-renewed; exchanged ones cannot be (§5.4).

---

## 7. Porting this to an agent / LLM / tool-calling system

### 7.1 The mapping

| Reference | Your system |
|---|---|
| alice | the human user |
| `web-app` (public, auth code + PKCE) | the chat/web front end |
| service-1 (Orders API) | the agent orchestrator — the thing that holds the user's token |
| service-2/3 (Billing, Payments) | tool services, MCP servers, retrieval services |
| service-4 (Ledger) | the system of record a tool finally touches |

The user logs in with `scope=openid delegate-to:<orchestrator-client-id>`. From then on every tool call
is an exchange, exactly as in §2.

### 7.2 The LLM is not a principal — this is the key design rule

Do not give the model a token, and do not create a Keycloak client for "the LLM". The model emits
*proposed* tool calls; it is untrusted text generation. The **orchestrator** holds the user's token,
decides whether a proposed call is permitted, and performs the exchange. The `act` chain then records
*services that acted*, which is what you can actually enforce and audit.

Concretely: if the model asks for `transfer_funds` and the orchestrator holds no `delegate-to:payments`
grant for this user, the exchange fails at Keycloak. Prompt injection cannot mint a token. That is the
whole security value of doing this — it is the agent-era version of the confused deputy problem, and
`may_act` is what closes it.

### 7.3 Fan-out, one exchange per tool

Per §5.1, exchange the user's subject token once per tool, each with `scope=delegate-to:<tool-client>`.
Cache the result per (user-session, tool) for the token's lifetime (§5.2) rather than exchanging on every
call in a loop.

A tool that itself calls another service repeats the pattern, and `act` nests another level — that is
precisely what the custom provider in §3.6 exists to preserve.

### 7.4 Per-tool authorisation

Two independent levers, use both:

- **FGAP `delegate` permission** — a global allowlist of *which clients may be delegated to at all*
  (§3.5, semantics in §5.5). Make this per-tool rather than the blanket grant the reference uses. It
  cannot express "the orchestrator may call tool X but tool X may not call tool Y" — for that, see below.
- **An approved call graph** (§5.6) — if your tools must not call each other arbitrarily, enforce the
  permitted (caller, target) pairs explicitly: at issuance in the exchange provider, and again at each
  tool by checking `act.client_id`. Do not expect `act` or FGAP to do this for you (§5.3, §5.5).
- **Optional client scope assignment** — only assign `delegate-to` to clients that legitimately need it.
  Note this is coarse: `delegate-to` is one parameterized scope covering every target, so removing it
  stops a client delegating *at all*, not delegating to a particular tool.

### 7.5 Long-running and background agents

§5.8 means delegated tokens outlive the user's session, so a background agent keeps working after the
user disconnects. Decide deliberately whether you want that.

If an agent must run longer than `accessTokenLifespan`, the delegated token cannot be refreshed (§5.4).
Options: hold the user's refresh token in the orchestrator and re-mint a subject token, then re-exchange;
or accept a bounded agent lifetime. **Untested here** — the reference never ran an agent past token
expiry, so prototype this early rather than discovering it late.

### 7.6 What you get for audit

Every tool invocation can log `sub` (the human) and the full `act` chain (the path) from the token it
validated, with no trust in anything the caller said about itself. For an agent system this is the
record that answers "which user caused this, and through which agent" — the question that is otherwise
very hard to answer once an LLM is in the loop.

### 7.7 Tools that are not OAuth clients

Plenty of tools are a Python function, not an HTTP service with a Keycloak client. Two options:

- Put them behind one tool-executor service that *is* a client; the `act` chain then ends at that
  executor, and the specific function called is recorded in your own logs, not in the token.
- Register each tool as its own client when you need per-tool authorisation at the IdP.

Choose based on whether you need Keycloak to enforce per-tool access, or only to record it.

---

## 8. Getting a broken PoC working — ordered checklist

Work top to bottom; each step depends on the ones above it.

1. **Features on?** Keycloak started with `KC_FEATURES=token-exchange-delegation,parameterized-scopes`.
   If `delegation:client` does not exist as a client scope, they are not enabled.
2. **Realm has `adminPermissionsEnabled: true`?** Required for §3.5.
3. **Every participating client has `standard.token.exchange.enabled = "true"`**, and each service has
   `serviceAccountsEnabled: true`.
4. **`delegate-to` scope exists** with the three mappers in §3.4 and **no** consent attributes, and is
   assigned as an optional scope to every client involved.
5. **FGAP `delegate` permission** names the clients that may be delegated to.
6. **Can the user log in and get `may_act`?** Check the access token has `aud` and `may_act` naming your
   orchestrator. If not, the scope request or §3.4 is wrong — stop here, nothing downstream can work.
7. **Can the orchestrator get its own `client_credentials` token?** That is the `actor_token`.
8. **Does one exchange succeed?** Run §2 by hand with curl before any application code. The error strings
   in §4.2 and §6 tell you which check failed. Assert that the issued token actually has `aud` and
   `may_act` — a denied target returns HTTP 200 with both missing rather than an error (§5.5).
9. **If you added an approved call graph** (§5.6), confirm the permitted hops still succeed, not only
   that the forbidden ones fail.
10. **Is `act` nesting past one hop?** If not, §6.3 — the custom provider is not loaded.
11. **Browser-specific failures** → §6.1 and §6.5.

### A decoder, for reading tokens while debugging

```bash
decode() { p=$(echo "$1" | cut -d. -f2 | tr '_-' '/+');
  while [ $((${#p} % 4)) -ne 0 ]; do p="$p="; done; echo "$p" | base64 -d | jq .; }
```

macOS `base64 -d` fails without correct padding — that padding loop is not optional. And when flattening
a nested `act` with jq, `recurse(.act?)` **hangs forever** on a token without `act`; use
`recurse(.act? // empty)`:

```bash
decode "$TOKEN" | jq -r '[.preferred_username // .sub]
  + ([recurse(.act? // empty) | .client_id? // empty] | reverse) | join(" -> ")'
```

---

## 9. Deliberately not solved here

- **Revocation that actually bites.** §5.8; short lifespans plus your own check at the tool boundary.
- **Agents outliving token expiry.** §7.5, untested.
- **Keeping the delegation token out of the browser.** The reference puts it in the browser on purpose,
  to make it visible during a demo. Production shape is a BFF: the server handles the OIDC callback,
  keeps the token in a server-side session, and proxies calls. With a BFF, §6.1 disappears entirely
  because there is no cross-origin request.
- **Upgrade safety.** The provider in §3.6 extends an internal SPI pinned to 26.8.1. Re-test on upgrade.
