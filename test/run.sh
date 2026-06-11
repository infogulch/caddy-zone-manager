#!/usr/bin/env sh
# Builds and runs the integration-test harness against the zone in .env.
#
# Expects a .env file at the module root declaring:
#   PROVIDER_JSON=<json-formatted provider configuration, e.g. provider name & token>
#   XCADDY_BUILD_ARGS=<extra args to build caddy with, e.g. --with github.com/libdns/cloudflare>
#
# Example:
#   LINODE_TOKEN=abc123
#   PROVIDER_JSON='{"name":"linode","api_token":"'$LINODE_TOKEN'"}'
#   XCADDY_BUILD_ARGS="--with github.com/caddy-dns/linode"
#
# Extra arguments are passed through to the harness (e.g. --dns-timeout 120s).
set -eu

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
set -a
. ./.env
set +a

: "${PROVIDER_JSON:?PROVIDER_JSON must be set in .env}"
: "${XCADDY_BUILD_ARGS:?XCADDY_BUILD_ARGS must be set}"

if ! command -v xcaddy >/dev/null 2>&1; then
    echo "xcaddy binary is required but not found in PATH" >&2
    exit 1
fi

bin=$(mktemp -d)/czm-test
trap 'rm -rf "$(dirname "$bin")"' EXIT
go build -o "$bin" ./test
xcaddy build --output "./test/caddy" --with github.com/infogulch/caddy-zone-manager=. $XCADDY_BUILD_ARGS >caddy-test-xcaddybuild.log 2>&1

"$bin" \
    -caddy "./test/caddy" \
    -provider-json "$PROVIDER_JSON" \
    "$@"
