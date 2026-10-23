package poc.keycloak.delegation;

import java.util.LinkedHashMap;
import java.util.Map;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.tokenexchange.TokenExchangeDelegationProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

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
