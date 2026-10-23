#!/usr/bin/env bash
# Run the whole POC without Docker: needs Java 21, Maven and Python 3.
#   ./run-local.sh        start Keycloak + 4 services, configure the realm, run the demo
#   ./run-local.sh stop   stop everything
set -euo pipefail
cd "$(dirname "$0")"
KC_VERSION=26.8.1
WORK=.local
KC_HOME=$WORK/keycloak-$KC_VERSION
mkdir -p "$WORK"

if [[ "${1:-}" == "stop" ]]; then
  for f in "$WORK"/*.pid; do [[ -f "$f" ]] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
  echo "stopped"; exit 0
fi

if [[ ! -d "$KC_HOME" ]]; then
  echo "downloading Keycloak $KC_VERSION ..."
  curl -sSfL -o "$WORK/kc.zip" \
    "https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/$KC_VERSION/keycloak-quarkus-dist-$KC_VERSION.zip"
  unzip -q "$WORK/kc.zip" -d "$WORK" && rm "$WORK/kc.zip"
fi

echo "building delegation-chain provider ..."
(cd keycloak/delegation-chain-provider && mvn -q -B package)
cp keycloak/delegation-chain-provider/target/delegation-chain-provider.jar "$KC_HOME/providers/"

echo "starting Keycloak (log: $WORK/keycloak.log) ..."
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
KC_FEATURES=token-exchange-delegation,parameterized-scopes \
  nohup "$KC_HOME/bin/kc.sh" start-dev --http-port=8080 > "$WORK/keycloak.log" 2>&1 &
echo $! > "$WORK/keycloak.pid"
until curl -sf http://localhost:8080/realms/master > /dev/null; do sleep 2; done

python3 keycloak/setup_realm.py

for i in 1 2 3 4; do
  next=$((i + 1))
  if (( i < 4 )); then
    export NEXT_SERVICE_URL="http://localhost:808$next/" NEXT_CLIENT_ID="service-$next"
  else
    unset NEXT_SERVICE_URL NEXT_CLIENT_ID
  fi
  SERVICE_NAME="service-$i" PORT="808$i" nohup python3 services/service.py > "$WORK/service-$i.log" 2>&1 &
  echo $! > "$WORK/service-$i.pid"
done
sleep 1

python3 demo.py
echo
echo "Keycloak admin console: http://localhost:8080/admin (admin/admin), realm 'rfc8693'"
echo "service logs: $WORK/service-*.log    stop with: ./run-local.sh stop"
