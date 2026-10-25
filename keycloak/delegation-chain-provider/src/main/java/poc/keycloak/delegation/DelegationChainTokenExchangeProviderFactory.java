package poc.keycloak.delegation;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public class DelegationChainTokenExchangeProviderFactory implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {

    public static final String ID = "delegation-chain";

    /** e.g. DELEGATION_ALLOWED_HOPS="service-1>service-2,service-2>service-3,service-3>service-4" */
    public static final String ALLOWED_HOPS_ENV = "DELEGATION_ALLOWED_HOPS";

    private static final Logger log = Logger.getLogger(DelegationChainTokenExchangeProviderFactory.class);

    private Map<String, Set<String>> allowedHops = Collections.emptyMap();

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new DelegationChainTokenExchangeProvider(allowedHops);
    }

    @Override
    public void init(Config.Scope config) {
        // Config.Scope first so it can be set with --spi-..., falling back to the environment.
        String raw = config.get("allowedHops", System.getenv(ALLOWED_HOPS_ENV));
        allowedHops = parseHops(raw);
        if (allowedHops.isEmpty()) {
            log.info("delegation-chain: no allowed-hop restriction, any client may delegate to any client");
        } else {
            log.infof("delegation-chain: approved hops %s", allowedHops);
        }
    }

    /** "a>b,a>c,b>d" -> {a=[b,c], b=[d]}. Blank/null means no restriction. */
    static Map<String, Set<String>> parseHops(String raw) {
        if (raw == null || raw.isBlank()) {
            return Collections.emptyMap();
        }
        Map<String, Set<String>> hops = new LinkedHashMap<>();
        for (String pair : raw.split(",")) {
            String[] parts = pair.trim().split(">");
            if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
                throw new IllegalArgumentException(
                        "Invalid " + ALLOWED_HOPS_ENV + " entry '" + pair + "', expected '<from>><to>'");
            }
            hops.computeIfAbsent(parts[0].trim(), k -> new LinkedHashSet<>()).add(parts[1].trim());
        }
        return hops;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE_DELEGATION);
    }

    @Override
    public int order() {
        // built-in "delegation" is 15, "standard" is 10: requests with an actor_token come here first
        return 20;
    }
}
