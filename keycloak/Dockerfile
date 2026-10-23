# --- build the delegation-chain provider ---
FROM maven:3.9-eclipse-temurin-21 AS provider
WORKDIR /build
COPY delegation-chain-provider/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY delegation-chain-provider/src ./src
RUN mvn -q -B package

# --- Keycloak with RFC 8693 delegation enabled ---
FROM quay.io/keycloak/keycloak:26.8.1 AS builder
ENV KC_FEATURES=token-exchange-delegation,parameterized-scopes
COPY --from=provider /build/target/delegation-chain-provider.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.1
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENV KC_FEATURES=token-exchange-delegation,parameterized-scopes
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
