#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${CI:-}" != "true" ]]; then
    echo "This smoke test is restricted to disposable CI environments." >&2
    exit 2
fi

ENV_FILE="$(mktemp)"
DUMP_FILE="$(mktemp)"
SEED_LOG="$(mktemp)"
API_KEY="$(openssl rand -hex 32)"
DB_PASSWORD="$(openssl rand -hex 32)"
BASE_URL="http://127.0.0.1:8000"

cleanup() {
    local status=$?
    if [[ $status -ne 0 ]]; then
        docker compose --env-file "$ENV_FILE" logs --no-color api db || true
    fi
    docker compose --env-file "$ENV_FILE" down --remove-orphans || true
    rm -f "$ENV_FILE" "$DUMP_FILE" "$SEED_LOG"
    exit "$status"
}
trap cleanup EXIT

umask 077
cat > "$ENV_FILE" <<EOF
DEVICETRUST_API_KEY=$API_KEY
POSTGRES_PASSWORD=$DB_PASSWORD
DATABASE_URL=postgresql+psycopg://devicetrust:$DB_PASSWORD@db:5432/devicetrust
EOF

dc() {
    docker compose --env-file "$ENV_FILE" "$@"
}

wait_for_api() {
    local status
    for _ in $(seq 1 60); do
        status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
            --header "X-API-Key: $API_KEY" "$BASE_URL/devices" || true)"
        if [[ "$status" == "200" ]]; then
            return 0
        fi
        sleep 2
    done
    echo "DeviceTrust API did not become database-ready within 120 seconds." >&2
    return 1
}

dc up --build --detach
wait_for_api

unauthenticated_status="$(curl --silent --output /dev/null --write-out '%{http_code}' "$BASE_URL/devices")"
if [[ "$unauthenticated_status" != "401" ]]; then
    echo "Expected unauthenticated API request to return 401; got $unauthenticated_status." >&2
    exit 1
fi

# The first seed creates only synthetic fixtures; a second run must fail closed.
dc exec -T api python -m app.seed
if dc exec -T api python -m app.seed >"$SEED_LOG" 2>&1; then
    echo "The second seed unexpectedly succeeded." >&2
    exit 1
fi
grep -Fq "Demo seed aborted before writing" "$SEED_LOG"

device_count="$(curl --fail --silent --show-error --header "X-API-Key: $API_KEY" \
    "$BASE_URL/devices" | jq 'length')"
if [[ "$device_count" -ne 3 ]]; then
    echo "Expected exactly 3 seeded devices; found $device_count." >&2
    exit 1
fi

product_json="$(curl --fail --silent --show-error -X POST "$BASE_URL/products" \
    --header "X-API-Key: $API_KEY" --header "Content-Type: application/json" \
    --data '{"manufacturer":"Compose Smoke Test","product_name":"PostgreSQL Persistence","external_reference":"CI-COMPOSE"}')"
product_id="$(jq -r '.id' <<<"$product_json")"

release_json="$(curl --fail --silent --show-error -X POST "$BASE_URL/products/$product_id/releases" \
    --header "X-API-Key: $API_KEY" --header "Content-Type: application/json" \
    --data '{"version":"1.0.0","release_reference":"CI-COMPOSE-1.0.0"}')"
release_id="$(jq -r '.id' <<<"$release_json")"

import_json="$(curl --fail --silent --show-error -X POST \
    "$BASE_URL/product-releases/$release_id/sbom?source_type=manual&source_reference=ci-compose-smoke" \
    --header "X-API-Key: $API_KEY" --header "Content-Type: application/json" \
    --data-binary "@samples/cold_chain_gateway_sbom.json")"
import_id="$(jq -r '.id' <<<"$import_json")"

for record_id in "$product_id" "$release_id" "$import_id"; do
    if [[ ! "$record_id" =~ ^[0-9]+$ ]]; then
        echo "API returned a non-numeric record ID." >&2
        exit 1
    fi
done

components_json="$(curl --fail --silent --show-error \
    "$BASE_URL/sbom/imports/$import_id/components" --header "X-API-Key: $API_KEY")"
component_count="$(jq 'length' <<<"$components_json")"
if [[ "$component_count" -lt 1 ]]; then
    echo "The persisted SBOM import contains no component occurrences." >&2
    exit 1
fi

dc restart api
wait_for_api
curl --fail --silent --show-error "$BASE_URL/product-releases/$release_id/sbom" \
    --header "X-API-Key: $API_KEY" |
    jq -e --argjson import_id "$import_id" 'any(.[]; .id == $import_id)' >/dev/null

dc restart db
wait_for_api
curl --fail --silent --show-error "$BASE_URL/audit/verify" \
    --header "X-API-Key: $API_KEY" | jq -e '.valid == true' >/dev/null

# Restore a consistent custom-format dump into a separate disposable database.
dc exec -T db pg_dump -U devicetrust -d devicetrust -Fc >"$DUMP_FILE"
dc exec -T db createdb -U devicetrust devicetrust_restore
dc exec -T db pg_restore -U devicetrust -d devicetrust_restore \
    --exit-on-error --no-owner --no-privileges <"$DUMP_FILE"

restored_import_count="$(dc exec -T db psql -U devicetrust -d devicetrust_restore -Atc \
    "SELECT count(*) FROM sbom_imports WHERE id = $import_id;" | tr -d '\r')"
if [[ "$restored_import_count" != "1" ]]; then
    echo "Restored database does not contain the product SBOM import." >&2
    exit 1
fi

restored_audit_count="$(dc exec -T db psql -U devicetrust -d devicetrust_restore -Atc \
    "SELECT count(*) FROM audit_log WHERE action = 'sbom.product_import';" | tr -d '\r')"
if [[ "$restored_audit_count" != "1" ]]; then
    echo "Restored database does not contain the corresponding SBOM audit entry." >&2
    exit 1
fi

dc exec -T db dropdb -U devicetrust devicetrust_restore
echo "Compose smoke passed: migrations, API auth, seed fail-closed behavior, product SBOM persistence, API/DB restart, audit verification and PostgreSQL backup/restore."
