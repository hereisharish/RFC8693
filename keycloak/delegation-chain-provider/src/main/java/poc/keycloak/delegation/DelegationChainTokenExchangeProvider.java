package poc.keycloak.delegation;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.Response;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.tokenexchange.TokenExchangeDelegationProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.CorsErrorResponseException;

/**
 * Keycloak's built-in delegation provider (feature "token-exchange-delegation") issues
 * {@code act = may_act(subject_token)}, nesting only the {@code act} of the actor_token.
 * In a service chain the history lives in the subject_token, so it is lost after one hop.
 * <p>
 * This provider appends the subject_token's {@code act} as the innermost nested {@code act}
 * (RFC 8693 section 4.1), so a token received by service-4 reads:
 * <pre>
 * sub: alice
 * act: { client_id: service-3, act: { client_id: service-2, act: { client_id: service-1 } } }
 * </pre>
 * All validation (may_act, actor_token, audience, FGAP "delegate" permission) is inherited unchanged.
 */
public class DelegationChainTokenExchangeProvider extends TokenExchangeDelegationProvider {

    private static final String MAY_ACT = "may_act";
    /** Surfaces as the "error" field on the TOKEN_EXCHANGE_ERROR audit event. */
    public static final String HOP_NOT_ALLOWED = "delegation_hop_not_allowed";

    /** actor client id -> client ids it is allowed to delegate to. Empty map = no restriction. */
    private final Map<String, Set<String>> allowedHops;

    public DelegationChainTokenExchangeProvider(Map<String, Set<String>> allowedHops) {
        this.allowedHops = allowedHops == null ? Collections.emptyMap() : allowedHops;
    }

    @Override
    protected void checkRequestedAudiences(TokenManager.AccessTokenResponseBuilder responseBuilder) {
        super.checkRequestedAudiences(responseBuilder);

        Map<String, Object> claims = responseBuilder.getAccessToken().getOtherClaims();
        enforceAllowedHops(claims);
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

    /**
     * Enforce the approved call graph. Keycloak's own checks (may_act, actor_token, FGAP "delegate")
     * answer "may this client act for this user at all" and "may anyone be delegated to this client",
     * but neither expresses a <em>pair</em>: with FGAP alone service-1 can mint a token for service-4
     * and skip the chain. This closes that, at issuance time.
     */
    private void enforceAllowedHops(Map<String, Object> claims) {
        if (allowedHops.isEmpty()) {
            return;
        }
        // Read the target from may_act on the token just built, not from getTargetAudienceClients():
        // that returns the RFC 8693 "audience" request parameter, which defaults to the calling client
        // itself when absent. The delegation target is whoever may_act names.
        if (!(claims.get(MAY_ACT) instanceof Map<?, ?> mayAct)) {
            return;  // not a delegation request
        }
        Object target = mayAct.get("client_id");
        if (target == null) {
            return;
        }
        String targetId = String.valueOf(target);
        String actor = client.getClientId();
        if (!allowedHops.getOrDefault(actor, Collections.emptySet()).contains(targetId)) {
            // event.error() finalises a TOKEN_EXCHANGE_ERROR so the refused hop is auditable; without
            // it the attempt is rejected but leaves no trace in the event log.
            event.detail("rejected_hop", actor + ">" + targetId);
            event.detail("audience", targetId);
            event.error(HOP_NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, "invalid_request",
                    "Delegation from " + actor + " to " + targetId + " is not an approved hop",
                    Response.Status.BAD_REQUEST);
        }
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
