#!/usr/bin/env sh
# Builds and runs the integration-test harness against the zone in .env.
#
# Expects a .env file at the module root declaring:
#   DOMAIN=<zone dedicated to testing — its records WILL be destroyed>
#   LINODE_TOKEN=<Linode API token>
#
# Extra arguments are passed through to the harness (e.g. --dns-timeout 120s).
set -eu

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
set -a
. ./.env
set +a

: "${DOMAIN:?DOMAIN must be set in .env}"
: "${LINODE_TOKEN:?LINODE_TOKEN must be set in .env}"

bin=$(mktemp -d)/czm-test
trap 'rm -rf "$(dirname "$bin")"' EXIT
go build -o "$bin" ./test

EXPECT_DOMAIN_RECORDS_WILL_BE_DESTROYED=1 \
"$bin" \
    --caddy ./caddy \
    --zone "$DOMAIN" \
    --provider-json "{\"name\":\"linode\",\"api_token\":\"$LINODE_TOKEN\"}" \
    "$@"
