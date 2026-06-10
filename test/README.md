# Integration test harness

Automated end-to-end validation that caddy-zone-manager produces correct DNS
mutations when run against a **real DNS provider**. The module's unit tests
cover internal consistency (record parsing, RDATA normalization, sync
planning, protection policies); this harness closes the gap those tests
cannot: does the provider actually update its nameservers correctly?

The contract is **JSON config in, real DNS out**. Each test case is a JSON
file in [`cases/`](cases/) describing a desired zone configuration and the
DNS state that should result. The harness is a generic executor that knows
nothing about specific tests: it applies each case's config to a running
Caddy process via `caddy reload --force` and polls the zone's authoritative
nameservers until the expected state converges or a deadline expires.

## Usage

The zone is assumed to be **exclusively dedicated to testing** — every record
in it will be destroyed. Confirmation is required via
`--expect-domain-records-will-be-destroyed` or
`EXPECT_DOMAIN_RECORDS_WILL_BE_DESTROYED=1`.

```sh
go build -o czm-test ./test
EXPECT_DOMAIN_RECORDS_WILL_BE_DESTROYED=1 ./czm-test \
    --caddy ./caddy \
    --zone example.com \
    --provider-json '{"name":"cloudflare","api_token":"..."}'
```

[`run.sh`](run.sh) wraps this for a `.env` file declaring `DOMAIN` and
`LINODE_TOKEN`, passing extra arguments through (e.g.
`sh test/run.sh --dns-timeout 300s --nameservers ns1.linode.com`).

| Flag | Default | Description |
|------|---------|-------------|
| `--caddy` | `caddy` | Path to a Caddy binary built with this module and the provider plugin |
| `--zone` | *(required)* | Zone name, e.g. `example.com` |
| `--provider-json` | *(required)* | Provider config as a JSON object string or `@path/to/file` |
| `--cases` | `test/cases` | Directory containing the `*.json` case files |
| `--config` | `./caddy-test.json` | Path the harness writes the per-step JSON config to |
| `--caddy-log` | `./caddy-test.log` | Path for Caddy's structured JSON log |
| `--run-log` | `./caddy-test-run.log` | Path for the harness's own structured log |
| `--admin-addr` | `localhost:2019` | Caddy Admin API address |
| `--dns-timeout` | `60s` | Maximum wait time per DNS assertion |
| `--dns-poll-interval` | `2s` | Interval between DNS polls |
| `--nameservers` | *(auto-discover)* | Comma-separated authoritative NS addresses; the **first** entry is the sticky assertion target. Required when the zone's public delegation doesn't point at the provider's nameservers |
| `--all-nameservers` | *(flag)* | Query every nameserver and require unanimity (slower, strict) |
| `--expect-domain-records-will-be-destroyed` | *(flag)* | Required confirmation |

## How a run works

1. **Pre-flight** (see `preflight` in [`main.go`](main.go)): verify the Caddy
   binary, pin an assertion nameserver, verify the zone is empty (DNS-side
   and provider-side), start Caddy.
2. **Cases**: execute every case file in lexicographic order — reload the
   generated config, scan Caddy's log for the zone-sync result, then assert
   DNS state (see [`runner.go`](runner.go)). Cases are **stateful and
   sequential**; conventions are documented in
   [`cases/README.md`](cases/README.md).
3. **Cleanup** (runs even after failures or a first Ctrl+C): two
   empty-mirror sweeps with different protection sets, a final emptiness
   check, and process/secret teardown. A second Ctrl+C aborts cleanup and
   exits immediately.

**Two-tier verdicts**: `critical` cases abort the run on failure; `advisory`
cases (provider-dependent record types, exact TTL enforcement) log FAIL and
continue, and a provider-side sync error turns an advisory failure into SKIP
("unsupported" rather than "broken").

Both log files are JSON lines. Every DNS query attempt in the entire run —
assertion polls, discovery, pre-flight, cleanup — is logged as a `dns_query`
event in the run log, so it is a complete record of every DNS exchange.
Per-step configs are logged with `dns_provider` redacted.

| Exit code | Meaning |
|------|---------|
| 0 | All critical cases passed (advisory failures may exist) |
| 1 | A critical case failed, or pre-flight aborted the run |
| 2 | Usage error (bad flags, missing confirmation) |
| 130 | Interrupted by the operator |

## File map

- [`main.go`](main.go) — flags, signal handling, pre-flight, run loop, cleanup
- [`runner.go`](runner.go) — case schema, loader (token substitution), step executor, sync-log scanning, run-log writer
- [`caddy.go`](caddy.go) — Caddy process lifecycle and `caddy reload`
- [`dns.go`](dns.go) — nameserver discovery, the single logged `query()` helper, presence/absence assertions
- [`config.go`](config.go) — per-step Caddy JSON config construction
- [`cases_test.go`](cases_test.go) — offline validation of the case files against the harness schema (runs in CI, no credentials needed)
- [`linode-zone-ttl.sh`](linode-zone-ttl.sh), [`linode-records.sh`](linode-records.sh) — Linode API helpers for test-zone SOA tuning and debugging

## Findings

Issues discovered while building and running this harness against Linode
(June 2026). The first is fixed in the module; the rest are environmental
behaviors the harness is designed around, some of which suggest module
improvements.

1. **Module bug (fixed): name-target RDATA defeated idempotency.** Linode
   echoes CNAME/NS/MX/SRV targets *without* the trailing dot they were
   declared with, so every name-target RRset compared unequal and was
   rewritten on **every sync**, forever. Fixed by `canonicalizeTargetToken`
   in [`../sync.go`](../sync.go); locked in by
   `TestSync_Idempotent_TargetTrailingDotNotRewritten`.

2. **One unsupported record blocks the whole zone sync.** The module's apply
   is all-or-nothing per zone: when Linode rejected an HTTPS record
   ("Unsupported DNS record type"), the entire `SetRecords` batch failed and
   *unrelated* pending changes were never applied, with the module retrying
   forever. The harness isolates advisory-type records to their own cases so
   this can't poison critical cases, and bails advisory cases out early after
   two consecutive sync failures. *Possible module improvement: per-RRset
   error isolation.*

3. **Linode quantizes record TTLs** to a fixed set (30, 120, 300, 3600,
   7200, …), silently rounding others up. Besides breaking exact-TTL
   assertions, a non-quantized configured TTL (e.g. 600) makes the module see
   a perpetual TTL mismatch and rewrite the RRset on every sync. Cases only
   use quantization-exact values. *Possible module improvement: surface a
   hint when a written TTL reads back different.*

4. **Akamai-fronted `ns1–5.linode.com` are caches, not classic
   authoritatives.** They serve per-RRset answers with *counting-down* TTLs;
   after a deletion or change, different anycast backends can keep serving
   different stale generations for up to the record's original TTL (24h at
   Linode's default `ttl_sec`). The RD bit appeared to influence freshness in
   one experiment but was coincidence (backend selection). Defenses: the
   per-run nonce is embedded in **record names** so each run queries
   never-before-cached names; the test zone's SOA `ttl_sec` is kept at 30s
   (`linode-zone-ttl.sh`); apex RRsets, which can't be renamed, get warn-only
   emptiness checks with provider-side state verified separately.

5. **Propagation pacing**: Linode publishes zone updates in batches; writes
   typically became visible on a pinned nameserver in 15–60 s, but bursts of
   consecutive writes (one per case) can queue several minutes deep —
   `--dns-timeout 300s` is a comfortable margin.
