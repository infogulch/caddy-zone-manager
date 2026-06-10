#!/usr/bin/env sh
# Debug helper: set the test zone's SOA timers to their minimums so that
# records created with "provider decides" TTLs (and the edge caches derived
# from them) expire quickly. Mirrors the "Edit SOA Record" screen in Cloud
# Manager: Default TTL / Refresh Rate / Retry Rate / Expire Rate.
set -eu
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
domain_id=$(curl -s -H "Authorization: Bearer $LINODE_TOKEN" "https://api.linode.com/v4/domains" \
  | python3 -c "import sys,json,os; ds=json.load(sys.stdin)['data']; print([d['id'] for d in ds if d['domain']==os.environ['DOMAIN']][0])")
curl -s -X PUT -H "Authorization: Bearer $LINODE_TOKEN" -H "Content-Type: application/json" \
  -d '{"ttl_sec": 30, "refresh_sec": 30, "retry_sec": 30, "expire_sec": 604800}' \
  "https://api.linode.com/v4/domains/$domain_id" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print({k: d.get(k) for k in ('domain','ttl_sec','refresh_sec','retry_sec','expire_sec')})"
