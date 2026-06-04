# caddy-zone-manager

A [Caddy](https://caddyserver.com) app that performs **desired-state
synchronization** of DNS records to a target zone, using Caddy's existing
[libdns](https://github.com/libdns/libdns) DNS-provider ecosystem.

You declare the records a zone should contain; on startup and on every config
reload, the module reconciles the zone to match — creating, updating, and
(optionally) deleting records via any `dns.providers.*` plugin.

It implements the feature proposed in
[caddyserver/caddy#7779](https://github.com/caddyserver/caddy/issues/7779) and
is modeled on [mholt/caddy-dynamicdns](https://github.com/mholt/caddy-dynamicdns).

> **Status:** young module. `sync_mode` is **required** (no default) so you make
> a conscious safety choice. Read [Ownership & safety](#ownership--safety)
> before using `mirror`.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Sync modes](#sync-modes)
- [Record directives](#record-directives)
- [Ownership & safety](#ownership--safety)
- [TTLs](#ttls)
- [Placeholders](#placeholders)
- [Multiple zones](#multiple-zones)
- [Equivalent JSON](#equivalent-json)
- [Provider requirements](#provider-requirements)
- [How reconciliation works](#how-reconciliation-works)
- [Limitations](#limitations)

## Install

Build a Caddy binary with this module and at least one DNS provider plugin via
[xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build \
    --with github.com/infogulch/caddy-zone-manager \
    --with github.com/caddy-dns/cloudflare
```

Pick whichever provider you use from [github.com/libdns](https://github.com/libdns)
(packaged for Caddy under [github.com/caddy-dns](https://github.com/caddy-dns)).

## Quick start

`caddy-zone-manager` is configured as a **global option** in the Caddyfile:

```caddyfile
{
    dns_zone example.com {
        provider cloudflare {env.CLOUDFLARE_API_TOKEN}

        # REQUIRED: report | upsert | mirror
        sync_mode upsert

        # default TTL for records that omit one (0 = let the provider decide)
        default_ttl 3600

        records {
            a     @    203.0.113.10
            aaaa  @    2001:db8::1        300
            cname www  example.com.
            txt   @    "v=spf1 -all"
            mx    @    10 mail.example.com.
        }
    }
}
```

Start Caddy as usual; the zone is reconciled on boot and on every reload.

## Sync modes

`sync_mode` selects how aggressively a zone is reconciled. It is **required**.

| Mode      | Creates/updates declared records | Deletes undeclared records | Notes |
|-----------|:--------------------------------:|:--------------------------:|-------|
| `report`  | no (dry run)                     | no                         | Logs pending changes only. Great for previewing. |
| `upsert`  | yes                              | **no**                     | Conservative. Safe default once the module stabilizes. |
| `mirror`  | yes                              | **yes** (managed-eligible) | Full desired-state reconciliation. Destructive — read [Ownership & safety](#ownership--safety). |

## Record directives

Record directives live in a `records { … }` block. Each block must be
**multi-line** (one record per line).

Single-line forms — **TTL is always the optional trailing field**:

```caddyfile
records {
    a       @      203.0.113.10                        # [ttl]
    aaaa    @      2001:db8::1            300          # [ttl]
    cname   www    example.com.                        # [ttl]
    ns      @      ns1.example.com.                    # [ttl]
    txt     @      "v=spf1 -all"                       # [ttl]
    caa     @      0 issue "letsencrypt.org"           # [ttl]
    mx      @      10 mail.example.com.   3600         # [ttl]
    srv     _sip._tcp 10 5 5060 sip.example.com.       # [ttl]
}
```

Multi-line forms for `mx` and `srv`:

```caddyfile
records {
    mx @ {
        preference 10
        target     mail.example.com.
        ttl        3600
    }

    srv _sip._tcp {
        priority 10
        weight   5
        port     5060
        target   sip.example.com.
    }
}
```

### Generic records (`rr`)

For any type not covered above (e.g. `TLSA`, `SVCB`, `HTTPS`, `DS`, …), use the
generic `rr` directive. It keeps the TTL in its zone-file-native position
(right after the name), and the data is standard presentation-format RDATA,
validated via libdns `RR.Parse()`:

> [!NOTE]
> Support for `rr` records is dependent on your libdns provider.

```caddyfile
records {
    rr _443._tcp 3600 TLSA "3 1 1 b760c12119c388736da724df..."
    rr @         300  HTTPS "1 . alpn=h2,h3"
}
```

| Field grammar | Directive |
|---|---|
| `a` / `aaaa` | `<name> <ip> [ttl]` |
| `cname` / `ns` | `<name> <target> [ttl]` |
| `txt` | `<name> <text> [ttl]` |
| `caa` | `<name> <flags> <tag> <value> [ttl]` |
| `mx` | `<name> <preference> <target> [ttl]` |
| `srv` | `<_service._proto[.name]> <priority> <weight> <port> <target> [ttl]` |
| `rr` | `<name> <ttl> <type> <data>` |

For `srv`, the `_service._proto[.name]` token is used verbatim as the record
name (which is exactly what DNS providers expect).

## Ownership & safety

The whole point of `mirror` is to delete records you didn't declare — so the
module provides filters to protect records it should never touch. **A protected
record is never modified or deleted, in any `sync_mode`.**

Declaring a record in `records {}` that is *also* protected is contradictory
and is **rejected at startup** — remove the declaration or disable the relevant
protection. (If you genuinely want to manage `_acme-challenge` records yourself,
use `protect none` or an explicit `protect` list that omits `caddy-acme`.)

### `protect [default|none|all|<policy...>]`

Configures the built-in protection policies for this zone. If omitted, the
module uses the default safety set:

```caddyfile
protect caddy-acme caddy-ech apex-ns soa
```

`protect` may be specified at most once per zone. If present, it replaces the
built-in policy set exactly, except for the convenience keywords:

| Policy / keyword | Meaning |
|---|---|
| `default` | Enable the default policy set: `caddy-acme caddy-ech apex-ns soa`. |
| `none` | Disable all built-in protection policies. Explicit `protect_rrset` rules still apply. |
| `all` | Enable every known built-in protection policy. Currently equivalent to `default`. |
| `caddy-acme` | Protect anything under `_acme-challenge[.<name>]`, regardless of type. This includes DNS-01 TXT records and `_acme-challenge` CNAME delegations. |
| `caddy-ech` | Protect `HTTPS`/`SVCB` records carrying an `ech=` SvcParam, which Caddy may publish for Encrypted ClientHello. |
| `apex-ns` | Protect `NS` records at the zone apex. Delegation `NS` records below the apex are not protected by this policy. |
| `soa` | Protect `SOA` records. |

Examples:

```caddyfile
protect default                  # explicit default
protect none                     # dangerous: no built-in protections
protect caddy-acme apex-ns soa   # disable caddy-ech only
```

> **Note:** Caddy does not expose a runtime inventory of the records it
> manages, so `caddy-acme` and `caddy-ech` are deliberately conservative static
> heuristics, not an authoritative guarantee. If you manage these records in
> unusual ways, add explicit `protect_rrset` rules.

> **ECH co-management caveat:** because protection is `(name, type)`-granular,
> if you *declare* an `HTTPS` record at a name where Caddy also publishes ECH,
> the live record will carry an `ech=` param and the whole RRset is protected —
> so your declared `HTTPS` record is **left untouched** (logged at WARN) rather
> than overwritten, to avoid clobbering Caddy's `ech=`. Manage that record
> outside this module, omit `caddy-ech` from `protect`, or disable ECH
> publication for that name.

### `protect_rrset <type> <name...>`

Protect specific RRsets by type and name. `*` matches any type.

```caddyfile
protect_rrset TXT _dmarc         # protect the _dmarc TXT RRset
protect_rrset MX  @              # protect the apex MX RRset
protect_rrset *   verification   # protect any RRset named "verification"
```

### Recommended workflow

1. Start with `sync_mode report` and review the logged output.
2. Move to `upsert` once the output looks right.
3. Only switch to `mirror` after confirming your `protect` and
   `protect_rrset` settings cover every record you want to keep.

## TTLs

A record's effective TTL is resolved in this order:

1. an explicit TTL on the record; if zero or unset then:
2. the zone's `default_ttl`; if zero or unset then:
3. the default TTL chosen by the DNS provider

TTL values accept a bare integer (seconds) or a whole-second Go/Caddy duration
(`1h`, `90m`, `300s`). Fractional TTLs such as `500ms` are rejected because DNS
TTLs are second-granular.

**Idempotency note:** when a record's effective TTL is `0`, the provider's
reported TTL is ignored when deciding whether the record is up to date, so a
zone with provider-chosen TTLs won't be needlessly rewritten on every sync. If
you set an explicit TTL (per-record or via `default_ttl`), that TTL *is*
enforced and compared.

## Placeholders

The module applies Caddy's replacer at provision time to zone names,
`protect_rrset` entries, and record fields (`name`, `type`, and `data`), so
`{env.*}`, `{file.*}`, etc. work in record data:

```caddyfile
records {
    rr _443._tcp 3600 TLSA "3 1 1 {file./config/tlsa-hash}"
}
```

Provider modules may support placeholders in their own configuration, but that
behavior is provider-specific rather than guaranteed by `caddy-zone-manager`.
TTL values are parsed while adapting the Caddyfile, so TTL placeholders are not
supported.

## Multiple zones

Declare each zone in its own `dns_zone` block. The option is repeatable, and
all blocks aggregate into one app instance:

```caddyfile
{
    dns_zone example.com {
        provider cloudflare {env.CLOUDFLARE_API_TOKEN}
        sync_mode upsert
        records { a @ 203.0.113.10 }
    }

    dns_zone app.example {
        provider cloudflare {env.CLOUDFLARE_API_TOKEN}
        sync_mode mirror
        records { a @ 203.0.113.20 }
    }
}
```

**Each `(zone, provider)` pair must be declared in exactly one block.**
Declaring the same zone twice with the *same* provider (including
trailing-dot/case variants like `example.com` and `example.com.`) is an error —
so a zone's complete desired state and safety filters always live in one place.

You *may* declare the same zone name more than once as long as each block uses a
**different** DNS provider (for example, to publish the same zone to two
providers). Each `(zone, provider)` pair is then reconciled independently, so
make sure every block carries the complete desired state and protection settings
for the records it manages — especially in `mirror` mode, which deletes
undeclared records.

## Equivalent JSON

The Caddyfile global option configures the `dns_zone` app. The equivalent
native JSON:

```json
{
  "apps": {
    "dns_zone": {
      "zones": [
        {
          "zone_name": "example.com",
          "dns_provider": {
            "name": "cloudflare",
            "api_token": "{env.CLOUDFLARE_API_TOKEN}"
          },
          "sync_mode": "upsert",
          "default_ttl": 3600000000000,
          "protect": ["caddy-acme", "caddy-ech", "apex-ns", "soa"],
          "protect_rrsets": [
            ["TXT", "_dmarc"]
          ],
          "records": [
            { "name": "@",   "type": "A",     "ttl": 0,             "data": "203.0.113.10" },
            { "name": "www", "type": "CNAME", "ttl": 0,             "data": "example.com." },
            { "name": "@",   "type": "MX",    "ttl": 3600000000000, "data": "10 mail.example.com." }
          ]
        }
      ]
    }
  }
}
```

Note that `default_ttl` and per-record `ttl` are expressed in **nanoseconds** in
JSON (Go `time.Duration`), e.g. `3600000000000` = 3600s.

## Provider requirements

A configured provider must implement the libdns interfaces the module needs:

- [`libdns.RecordGetter`](https://pkg.go.dev/github.com/libdns/libdns#RecordGetter)
- [`libdns.RecordSetter`](https://pkg.go.dev/github.com/libdns/libdns#RecordSetter)
- [`libdns.RecordDeleter`](https://pkg.go.dev/github.com/libdns/libdns#RecordDeleter)

Most `caddy-dns` providers implement all three. If a provider is missing one,
provisioning fails.

## How reconciliation works

For each zone, independently and concurrently:

1. **Fetch:** call `GetRecords` to read the live zone state and parse declared
   records into typed libdns records.
2. **Mark protected RRsets:** scan every live record through the configured
   protection policies. Any `(name, type)` pair containing at least one
   protected record is flagged — it is never written or deleted.
3. **Plan creates/updates:** for each declared RRset:
   - If the RRset is live-protected (data-dependent, e.g. an `HTTPS` record
     Caddy has augmented with an `ech=` param your declaration doesn't carry)
     → log a warning and leave it untouched.
   - If the RRset doesn't exist in the live zone → **create**.
   - If the live RRset matches (same canonical RDATA and effective TTL for
     every declared member; in `upsert` mode the live RRset may also contain
     extra undeclared members and still be considered up-to-date) → **skip**
     (unchanged).
   - Otherwise → **update**. `SetRecords` replaces the live RRset atomically.
     In `mirror` mode only the declared members are written, so any live record
     in that RRset that was not declared is removed. In `upsert` mode the
     declared members are merged with undeclared live members before the write,
     so no sibling record within the RRset is lost. In both modes, any member
     with a desired TTL of `0` ("provider decides") inherits the current TTL
     for that record if one already exists, to avoid resetting provider-assigned
     TTLs for members that aren't actually changing.
4. **Plan deletes:** scan live RRsets for entries that are neither declared
   nor protected — these are the deletion candidates.
5. **Execute sync depending on the mode:**
   - `report` — log the planned creates, updates, and deletes; mutate nothing.
   - `upsert` — write creates and updates via `SetRecords`; undeclared RRsets
     are not deleted (counted and logged as `would_delete`); undeclared records
     *within* a declared RRset are also preserved by merging them into the
     `SetRecords` payload.
   - `mirror` — write creates and updates via `SetRecords`; delete candidates
     via `DeleteRecords`.

**Idempotency:** re-running with no config changes performs zero writes. RDATA
is compared in libdns's canonical presentation form, so cosmetic provider
differences like IPv6 compression (`AAAA`), flag and quoting style (`CAA`), or
internal whitespace (`MX`/`SRV`) don't trigger a rewrite. `HTTPS`/`SVCB`
records are compared verbatim — libdns serializes their `SvcParams` from a Go
map, so re-serializing could produce a different order and make equal records
compare unequal.

A failure in one zone is logged and isolated; it does not abort other zones.
The initial sync is retried with exponential backoff to tolerate a not-yet-ready
network at boot.

## Limitations

- **Sync on startup/reload only.** Continuous drift correction (a periodic
  re-sync interval) is a future enhancement, not in this release.
- **No zone-file import**, DNSSEC management, or DANE/TLSA certificate-lifecycle
  automation. You can *publish* TLSA records via `rr`, but rollover timing is
  out of scope.
- **Caddy protection policies are heuristic**, not an authoritative list of
  Caddy-managed records (see above).
- Record blocks must be **multi-line** (one record per line).

## License

Apache-2.0. See [LICENSE](LICENSE).
