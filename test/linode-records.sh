#!/usr/bin/env sh
# Debug helper: list the test domain's records via the Linode API.
set -eu
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
domain_id=$(curl -s -H "Authorization: Bearer $LINODE_TOKEN" "https://api.linode.com/v4/domains" \
  | python3 -c "import sys,json,os; ds=json.load(sys.stdin)['data']; print([d['id'] for d in ds if d['domain']==os.environ['DOMAIN']][0])")
curl -s -H "Authorization: Bearer $LINODE_TOKEN" "https://api.linode.com/v4/domains/$domain_id/records" \
  | python3 -m json.tool
