package zonemanager

import (
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

const maxDNSTTLSeconds = 1<<32 - 1

func validateTTL(ttl time.Duration, context string) error {
	if ttl < 0 {
		return fmt.Errorf("%s: TTL must be non-negative", context)
	}
	if ttl%time.Second != 0 {
		return fmt.Errorf("%s: TTL must be a whole number of seconds", context)
	}
	if ttl > maxDNSTTLSeconds*time.Second {
		return fmt.Errorf("%s: TTL must be less than 2^32 seconds", context)
	}
	return nil
}

// normalizeRecords returns a copy of zc.Records with the Caddy replacer applied
// to each record's field, fills in the zone's default TTL where a record omits
// one, and validates each record by parsing its RDATA. It fails fast (with
// record context) on bad data so configuration errors surface at provision time
// rather than at sync time.
func normalizeRecords(records []libdns.RR, repl *caddy.Replacer, defaultTTL caddy.Duration, zone string) (newRecords []libdns.RR, err error) {
	newRecords = make([]libdns.RR, 0, len(records))
	for i, rr := range records {
		rr.Name = strings.TrimSpace(repl.ReplaceAll(rr.Name, ""))
		rr.Type = strings.ToUpper(strings.TrimSpace(repl.ReplaceAll(rr.Type, "")))
		rr.Data = repl.ReplaceAll(rr.Data, "")

		if rr.Name == "" {
			return nil, fmt.Errorf("record %d: name is required (use \"@\" for the zone apex)", i)
		}
		if rr.Type == "" {
			return nil, fmt.Errorf("record %d (%s): type is required", i, rr.Name)
		}
		if err := validateOwnerName(rr.Name, zone, fmt.Sprintf("record %d (%s %s)", i, rr.Name, rr.Type)); err != nil {
			return nil, err
		}

		// Apply the zone default TTL when the record didn't specify one.
		if rr.TTL == 0 && defaultTTL != 0 {
			rr.TTL = time.Duration(defaultTTL)
		}

		if err := validateTTL(rr.TTL, fmt.Sprintf("record %d (%s %s %q)", i, rr.Name, rr.Type, rr.Data)); err != nil {
			return nil, err
		}

		// Validate by parsing into a typed libdns.Record.
		if _, err := rr.Parse(); err != nil {
			return nil, fmt.Errorf("record %d (%s %s %q): %w", i, rr.Name, rr.Type, rr.Data, err)
		}

		newRecords = append(newRecords, rr)
	}
	return newRecords, nil
}

func validateZoneName(zone string) error {
	if zone == "" || zone == "." {
		return fmt.Errorf("zone name is required")
	}
	if _, ok := dns.IsDomainName(zone); !ok {
		return fmt.Errorf("invalid zone name %q", zone)
	}
	return nil
}

func validateOwnerName(name, zone, context string) error {
	if name == "" {
		return fmt.Errorf("%s: name is required", context)
	}
	abs := strings.ToLower(libdns.AbsoluteName(name, zone))
	if _, ok := dns.IsDomainName(abs); !ok {
		return fmt.Errorf("%s: invalid DNS name %q", context, name)
	}
	if !nameInZone(abs, zone) {
		return fmt.Errorf("%s: DNS name %q is outside zone %q", context, name, zone)
	}
	return nil
}

func nameInZone(absName, zone string) bool {
	absName = strings.ToLower(strings.TrimSpace(absName))
	zone = strings.ToLower(strings.TrimSpace(zone))
	return absName == zone || strings.HasSuffix(absName, "."+zone)
}

// parsedRecords converts the zone's desired RRs into typed libdns.Records.
// Records have already been validated during Provision, so a parse failure
// here is treated as a programming error in the caller's flow and surfaced.
func (zc *ZoneConfig) parsedRecords() ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(zc.Records))
	for i := range zc.Records {
		rec, err := zc.Records[i].Parse()
		if err != nil {
			return nil, fmt.Errorf("record %d (%s %s): %w",
				i, zc.Records[i].Name, zc.Records[i].Type, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
