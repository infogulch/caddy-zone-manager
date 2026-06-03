package zonemanager

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/libdns/libdns"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("dns_zone", parseApp)
}

// parseApp configures one `dns_zone` global option from the Caddyfile. The
// option is repeatable so that multiple zones can be declared, each in its own
// block; the blocks aggregate into a single app instance via the existingVal
// argument. Each (zone, provider) pair must be declared in exactly one block:
// validation rejects declaring the same zone with the same provider twice, so
// its complete desired state and safety filters always live in one place
// (important since `mirror` mode deletes undeclared records). The same zone
// name may be declared with different providers; each pair is reconciled
// independently.
//
// Syntax:
//
//	dns_zone <zone> {
//		provider <name> ...
//		sync_mode report|upsert|mirror
//		default_ttl <ttl>
//		records {
//			a|aaaa  <name> <ip>                              [ttl]
//			cname   <name> <target>                          [ttl]
//			ns      <name> <target>                          [ttl]
//			txt     <name> <text>                            [ttl]
//			caa     <name> <flags> <tag> <value>             [ttl]
//			mx      <name> <preference> <target>             [ttl]
//			mx      <name> { preference <n>; target <t>; ttl <ttl> }
//			srv     <_svc._proto[.name]> <priority> <weight> <port> <target> [ttl]
//			srv     <_svc._proto[.name]> { priority <n>; weight <n>; port <n>; target <t>; ttl <ttl> }
//			rr      <name> <ttl> <type> <data>
//		}
//		protect default|none|all|caddy-acme|caddy-ech|apex-ns|soa...
//		protect_rrset <type> <name...>
//	}
//
// TTLs may be given as a bare integer (seconds) or a whole-second Go/Caddy
// duration (e.g. "1h"). Zone names, protect_rrset entries, and record
// name/type/data fields support Caddy placeholders, which are resolved at
// provision time.
func parseApp(d *caddyfile.Dispenser, existingVal any) (any, error) {
	app := new(App)
	if prev, ok := existingVal.(httpcaddyfile.App); ok && len(prev.Value) > 0 {
		if err := json.Unmarshal(prev.Value, app); err != nil {
			return nil, fmt.Errorf("merging dns_zone configurations: %v", err)
		}
	}

	// consume the option name
	if !d.Next() {
		return nil, d.ArgErr()
	}

	// zone name is the directive argument
	if !d.NextArg() {
		return nil, d.Err("dns_zone requires a zone name argument")
	}
	zoneName := d.Val()
	if d.NextArg() {
		return nil, d.Err("dns_zone takes exactly one zone name argument")
	}

	// Parse this block into a fresh config. Duplicate (zone, provider) pairs are
	// detected later during app validation, after placeholder replacement and
	// zone-name normalization.
	zc := new(ZoneConfig)

	// Take the zone name as-is; it needs to run through the replacer before
	// normalization and duplicate checking.
	zc.ZoneName = zoneName

	seenProvider := false
	seenSyncMode := false
	seenDefaultTTL := false
	seenRecords := false
	seenProtect := false

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "provider":
			if seenProvider {
				return nil, d.Err("provider may be specified at most once per dns_zone block")
			}
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			provName := d.Val()
			modID := "dns.providers." + provName
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}
			zc.DNSProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)
			seenProvider = true

		case "sync_mode":
			if seenSyncMode {
				return nil, d.Err("sync_mode may be specified at most once per dns_zone block")
			}
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			zc.SyncMode = d.Val()
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			seenSyncMode = true

		case "default_ttl":
			if seenDefaultTTL {
				return nil, d.Err("default_ttl may be specified at most once per dns_zone block")
			}
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := parseTTL(d.Val())
			if err != nil {
				return nil, d.WrapErr(err)
			}
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			zc.DefaultTTL = caddy.Duration(dur)
			seenDefaultTTL = true

		case "records":
			seenRecords = true
			if len(d.RemainingArgs()) > 0 {
				return nil, d.Err("records does not take arguments; use a records { ... } block")
			}
			for n := d.Nesting(); d.NextBlock(n); {
				rec, err := parseRecord(d)
				if err != nil {
					return nil, err
				}
				zc.Records = append(zc.Records, rec)
			}
			// NextBlock leaves the cursor on "}" after consuming an empty block,
			// but leaves it on "records" when no block was present at all.
			if d.Val() != "}" {
				return nil, d.Err("records requires a block")
			}

		case "protect":
			if seenProtect {
				return nil, d.Err("protect may be specified at most once per dns_zone block")
			}
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.Err("protect requires default, none, all, or one or more policy names")
			}
			zc.Protect = args
			seenProtect = true

		case "protect_rrset":
			args := d.RemainingArgs()
			if len(args) < 2 {
				return nil, d.Err("protect_rrset requires a type and at least one name: protect_rrset <type> <name...>")
			}
			zc.ProtectRRsets = append(zc.ProtectRRsets, args)

		default:
			return nil, d.Errf("unrecognized dns_zone directive: %s", d.Val())
		}
	}

	if !seenRecords {
		return nil, d.Err("dns_zone requires a records block")
	}

	app.Zones = append(app.Zones, zc)

	return httpcaddyfile.App{
		Name:  "dns_zone",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// parseRecord parses a single record directive within a `records {}` block.
// The dispenser cursor is positioned on the record-type keyword. Records are
// stored as generic libdns.RR; parsing/validation of the RDATA is deferred to
// Provision (after placeholder resolution).
func parseRecord(d *caddyfile.Dispenser) (libdns.RR, error) {
	keyword := strings.ToLower(d.Val())

	switch keyword {
	case "a", "aaaa":
		rest, ttl, err := lineArgs(d, 2)
		if err != nil {
			return libdns.RR{}, err
		}
		return libdns.RR{Name: rest[0], TTL: ttl, Type: strings.ToUpper(keyword), Data: rest[1]}, nil

	case "cname", "ns":
		rest, ttl, err := lineArgs(d, 2)
		if err != nil {
			return libdns.RR{}, err
		}
		return libdns.RR{Name: rest[0], TTL: ttl, Type: strings.ToUpper(keyword), Data: rest[1]}, nil

	case "txt":
		rest, ttl, err := lineArgs(d, 2)
		if err != nil {
			return libdns.RR{}, err
		}
		return libdns.RR{Name: rest[0], TTL: ttl, Type: "TXT", Data: rest[1]}, nil

	case "caa":
		rest, ttl, err := lineArgs(d, 4)
		if err != nil {
			return libdns.RR{}, err
		}
		// flags tag "value" — matches libdns CAA presentation format.
		data := fmt.Sprintf("%s %s %q", rest[1], rest[2], rest[3])
		return libdns.RR{Name: rest[0], TTL: ttl, Type: "CAA", Data: data}, nil

	case "mx":
		return parseMX(d)

	case "srv":
		return parseSRV(d)

	case "rr":
		// rr <name> <ttl> <type> <data> — TTL is in its zonefile-native
		// position (after the name), not trailing.
		args := d.RemainingArgs()
		if len(args) != 4 {
			return libdns.RR{}, d.Err("rr requires: rr <name> <ttl> <type> <data>")
		}
		ttl, err := parseTTL(args[1])
		if err != nil {
			return libdns.RR{}, d.WrapErr(err)
		}
		return libdns.RR{Name: args[0], TTL: ttl, Type: strings.ToUpper(args[2]), Data: args[3]}, nil

	default:
		return libdns.RR{}, d.Errf("unrecognized record type: %s", keyword)
	}
}

// parseMX handles both the single-line and multi-line MX forms.
func parseMX(d *caddyfile.Dispenser) (libdns.RR, error) {
	args := d.RemainingArgs()

	var name, preference, target string
	var ttl time.Duration
	inBlock := false

	for n := d.Nesting(); d.NextBlock(n); {
		inBlock = true
		key := d.Val()
		val, err := requireArg(d, key)
		if err != nil {
			return libdns.RR{}, err
		}
		switch key {
		case "preference":
			preference = val
		case "target":
			target = val
		case "ttl":
			ttl, err = parseTTL(val)
			if err != nil {
				return libdns.RR{}, d.WrapErr(err)
			}
		default:
			return libdns.RR{}, d.Errf("unrecognized mx subkey: %s", key)
		}
	}

	if inBlock {
		if len(args) != 1 {
			return libdns.RR{}, d.Err("mx block form takes only: mx <name> { ... }")
		}
		name = args[0]
		if preference == "" || target == "" {
			return libdns.RR{}, d.Err("mx block requires preference and target")
		}
	} else {
		// single-line: <name> <preference> <target> [ttl]
		rest, t, err := splitTrailingTTL(args, 3)
		if err != nil {
			return libdns.RR{}, d.WrapErr(err)
		}
		name, preference, target, ttl = rest[0], rest[1], rest[2], t
	}

	return libdns.RR{Name: name, TTL: ttl, Type: "MX", Data: preference + " " + target}, nil
}

// parseSRV handles both the single-line and multi-line SRV forms. The record
// name keeps its _service._proto[.name] presentation form, which is exactly
// what libdns expects for the RRset name.
func parseSRV(d *caddyfile.Dispenser) (libdns.RR, error) {
	args := d.RemainingArgs()

	var name, priority, weight, port, target string
	var ttl time.Duration
	inBlock := false

	for n := d.Nesting(); d.NextBlock(n); {
		inBlock = true
		key := d.Val()
		val, err := requireArg(d, key)
		if err != nil {
			return libdns.RR{}, err
		}
		switch key {
		case "priority":
			priority = val
		case "weight":
			weight = val
		case "port":
			port = val
		case "target":
			target = val
		case "ttl":
			ttl, err = parseTTL(val)
			if err != nil {
				return libdns.RR{}, d.WrapErr(err)
			}
		default:
			return libdns.RR{}, d.Errf("unrecognized srv subkey: %s", key)
		}
	}

	if inBlock {
		if len(args) != 1 {
			return libdns.RR{}, d.Err("srv block form takes only: srv <_svc._proto[.name]> { ... }")
		}
		name = args[0]
		if priority == "" || weight == "" || port == "" || target == "" {
			return libdns.RR{}, d.Err("srv block requires priority, weight, port, and target")
		}
	} else {
		// single-line: <name> <priority> <weight> <port> <target> [ttl]
		rest, t, err := splitTrailingTTL(args, 5)
		if err != nil {
			return libdns.RR{}, d.WrapErr(err)
		}
		name, priority, weight, port, target, ttl = rest[0], rest[1], rest[2], rest[3], rest[4], t
	}

	data := strings.Join([]string{priority, weight, port, target}, " ")
	return libdns.RR{Name: name, TTL: ttl, Type: "SRV", Data: data}, nil
}

// lineArgs reads the remaining single-line args for a record directive that
// has `required` positional fields followed by an optional trailing TTL.
func lineArgs(d *caddyfile.Dispenser, required int) (rest []string, ttl time.Duration, err error) {
	args := d.RemainingArgs()
	rest, ttl, err = splitTrailingTTL(args, required)
	if err != nil {
		return nil, 0, d.WrapErr(err)
	}
	return rest, ttl, nil
}

// splitTrailingTTL splits args into the first `required` positional fields plus
// an optional trailing TTL field.
func splitTrailingTTL(args []string, required int) (rest []string, ttl time.Duration, err error) {
	switch len(args) {
	case required:
		return args, 0, nil
	case required + 1:
		ttl, err = parseTTL(args[required])
		if err != nil {
			return nil, 0, err
		}
		return args[:required], ttl, nil
	default:
		return nil, 0, fmt.Errorf("expected %d arguments (plus optional ttl), got %d", required, len(args))
	}
}

// requireArg advances to and returns the single argument expected after a
// block subkey, erroring if it is missing.
func requireArg(d *caddyfile.Dispenser, key string) (string, error) {
	if !d.NextArg() {
		return "", d.Errf("%s requires a value", key)
	}
	val := d.Val()
	if d.NextArg() {
		return "", d.ArgErr()
	}
	return val, nil
}

// parseTTL parses a TTL token. A bare integer is interpreted as seconds; any
// other value is parsed as a Caddy/Go duration (e.g. "1h", "300s"). DNS TTLs
// are second-granular, so sub-second durations are rejected.
func parseTTL(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("ttl cannot be negative: %d", n)
		}
		return time.Duration(n) * time.Second, nil
	}
	dur, err := caddy.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q: %w", s, err)
	}
	if dur < 0 {
		return 0, fmt.Errorf("ttl cannot be negative: %s", s)
	}
	if dur%time.Second != 0 {
		return 0, fmt.Errorf("ttl must be a whole number of seconds: %s", s)
	}
	return dur, nil
}
