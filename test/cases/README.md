# Test case files

JSON case files executed by the harness in lexicographic order. Each file
performs exactly **one** `caddy reload`; multi-reload scenarios (establish
state, then assert behavior on a follow-up reload) are split into `a`/`b`
files. The harness is a dumb executor with no per-case logic — adding or
modifying cases requires no Go changes, but see the conventions below.
`cases_test.go` validates every file against the harness schema offline.

## Schema

```jsonc
{
  "name": "string",          // optional; defaults to the filename
  "description": "string",   // optional
  "tier": "critical",        // "critical" aborts the run on failure;
                             // "advisory" logs FAIL (or SKIP on provider
                             // error) and continues. Default: critical.

  // ZoneConfig fields to apply. zone_name and dns_provider are injected
  // by the harness from CLI flags.
  "apply_zone": {
    "sync_mode": "report" | "upsert" | "mirror",
    "default_ttl": 0,          // nanoseconds; 0 = provider decides
    "protect": ["default"],    // omit to use the module default
    "protect_rrsets": [["TYPE", "name"]],
    "records": [ { "name": "…", "type": "…", "ttl": 0, "data": "…" } ]
  },

  // Records that must be present in DNS after reload. data is optional:
  // when present it is compared after canonical normalization; when absent
  // only (name, type) presence is asserted — needed for NS/SOA whose
  // provider-controlled data can't be known in advance. ttl > 0 also
  // asserts the exact authoritative TTL.
  "expect_rr": [ { "name": "…", "type": "…", "data": "…", "ttl": 0 } ],

  // Records that must be absent. Without data: NXDOMAIN or NODATA. With
  // data: a NOERROR answer is also accepted as long as no record in the
  // RRset carries that RDATA — required when asserting one sibling gone
  // while another remains (044b).
  "absent_rr": [ { "name": "…", "type": "…", "data": "…" } ],

  // Integer fields from the zone-sync log line emitted after this reload.
  // Only listed fields are checked; a "_min" suffix asserts >= instead of
  // equality. Only assert fields the mode emits — report: would_create,
  // would_update, would_delete, matched; upsert: created, updated, matched,
  // would_delete; mirror: created, updated, deleted, matched.
  "expect_sync": { "created": 0, "would_delete_min": 1 }
}
```

Record names use `@` for the zone apex; relative labels are qualified
against the zone. TTLs are nanoseconds (`300000000000` = 300 s) and must be
values the provider serves exactly — Linode quantizes to a fixed set (30,
120, 300, 3600, 7200, …) and silently rounds others up, which breaks both
exact-TTL assertions and module idempotency. Cases use 300 s and 3600 s.

## Tokens

Replaced by raw byte substitution on the file contents before JSON parsing,
so they work in any string field:

- `{{nonce}}`: the per-run 8-hex-char nonce. Embedded in every non-apex
  **record name** (`host1-{{nonce}}`, `sub-{{nonce}}`, `_test-{{nonce}}._tcp`)
  so each run queries never-before-seen names — immune to stale per-RRset
  caches on the Akamai-fronted nameservers (see Findings in
  [`../README.md`](../README.md)) — and in TXT data so assertions are
  provably about this run's writes. Apex (`@`) records cannot be renamed;
  their cases are advisory and their pre-flight checks warn-only.
- `{{zone}}`: the normalized zone FQDN (lowercase, one trailing dot). Used
  wherever RDATA must reference a name inside the zone (CNAME/MX/SRV
  targets), which case files cannot otherwise know.

## Cumulative-state convention

Cases are **stateful and sequential**. Every upsert-mode case re-declares the
**critical-type** records established by earlier cases (upsert never deletes,
but omitting a record from a later mirror-mode case *does* delete it).
Inserting a new case mid-sequence requires updating the record lists of every
later case that builds on that state.

**Advisory isolation:** records of advisory-tier types (AAAA, MX, CAA, SRV,
sub-NS, HTTPS) are declared *only* in their own introducing case (011,
014–018) and never carried forward. The module's sync apply is all-or-nothing
per zone, so a provider that rejects one record type (e.g. Linode and HTTPS)
would otherwise fail every later sync and poison the critical cases. Each
advisory case declares the cumulative critical set plus only its own record,
so an unsupported type can affect nothing but its own case (SKIP). On
supporting providers, advisory records survive the upsert phase undeclared
and are deleted by the first mirror case (040); 043's absence sweep holds
either way.

Phase boundaries (critical carried set; names abbreviated — all carry the
nonce suffix):

- After 018: host1 A, host3 TXT, host4 CNAME (advisory records may also
  exist live, per above).
- After 033: same with host1 → 203.0.113.11 and host3 → czm-updated TXT,
  plus host6 A (ttl 3600s) and host7 A; host3 carries an undeclared TXT
  sibling planted in 023a.
- After 043: the zone is empty of test records (043's absent_rr sweeps all
  test names/types created so far, including advisory ones).
- After 054b: host3 keep-TXT is gone (deleted by 050/051's empty mirror);
  host8 TXT and _acme-challenge.host1 TXT remain. 060/061 are exact copies
  of 054a/054b — the last upsert and mirror steps.

## Case groups

| Range | Theme |
|-------|-------|
| 001–002 | Report mode mutates nothing and plans stably across reloads |
| 010–018 | Upsert record-type coverage, one new type per case (A, AAAA, TXT, CNAME, MX, CAA, SRV, sub-NS, HTTPS) |
| 020–023 | Upsert updates values; preserves undeclared records and undeclared siblings within an RRset |
| 030–033 | TTL handling: explicit, default_ttl, ttl-0 idempotency, TTL change |
| 040–044 | Mirror creates/updates/deletes; empties the zone; removes one sibling while keeping another |
| 050–054 | Protection: apex NS/SOA survive an empty mirror, protect_rrsets, protect none, caddy-acme heuristic |
| 060–063 | Idempotency: identical reloads and cosmetic RDATA differences (IPv6 compression, CAA quoting) cause zero writes |

Notes that keep specific cases honest:

- **Planting (`a`/`b` splits)**: a record that must *survive* a later config
  (023b, 044b, 052b, 054b) is planted by an earlier `a` case. For the
  protection cases the plant must run **without** the protection active —
  the module rejects records that are both declared and protected at
  provision time — and the `b` step enables the protection and omits the
  declaration. 054's `_acme-challenge.host1` TXT also survives the default
  cleanup sweep, which is why cleanup runs a second pass with `caddy-acme`
  disabled.
- **014/015 (apex MX/CAA)** share the apex with the protected NS/SOA;
  **013 (CNAME)** must be on a non-apex name.
- **017 (sub-NS)**: authoritative servers answer NS queries for a delegated
  sub-name with a referral (records in the Authority section); the harness's
  presence check accepts Authority-section matches for NS/SOA only.
- **018 (HTTPS)**: stands in for the Caddyfile `rr` directive (in native
  JSON every record is already a generic RR, so a separate `rr` case would
  duplicate 012) and exercises verbatim comparison; advisory because
  provider support varies — Linode rejects it (SKIP).
- **022 (preserves undeclared)**: host6 is established by declaring it in
  021's record list, then omitted in 022 — no out-of-band provider access
  needed.
- **053 (protect none)**: report mode with no records and no protections
  makes the apex NS/SOA themselves delete candidates (`would_delete_min: 1`).
- **060/061**: rely on `caddy reload --force`; without it Caddy
  short-circuits byte-identical configs and no sync line is ever emitted.
