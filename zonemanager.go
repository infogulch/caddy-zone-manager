// Package zonemanager implements a Caddy app that performs desired-state
// synchronization of DNS records to a target zone using Caddy's existing
// libdns-based DNS provider ecosystem.
package zonemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// Sync modes control how aggressively a zone is reconciled toward its
// declared desired state. See the package documentation.
const (
	// syncModeReport computes and logs the diff but performs no mutations.
	syncModeReport = "report"
	// syncModeUpsert creates/updates declared records but never deletes
	// records that aren't declared.
	syncModeUpsert = "upsert"
	// syncModeMirror performs full desired-state reconciliation, including
	// deletion of managed-eligible records that are not declared.
	syncModeMirror = "mirror"
)

// App is a Caddy app that keeps a set of DNS zones in sync with a declared
// desired state. Multiple `dns_zone` global-option blocks aggregate into a
// single App instance. Duplicate (zone, provider) pairs are rejected during
// validation.
type App struct {
	// Zones to manage (FQDN; trailing dot optional). Native JSON uses an array;
	// each zone's name is stored in ZoneConfig.ZoneName.
	Zones []*ZoneConfig `json:"zones,omitempty"`

	ctx             caddy.Context
	logger          *zap.Logger
	normalizedZones []*ZoneConfig
	cancel          context.CancelFunc
	wg              *sync.WaitGroup // used in App.Start/Stop
}

// ZoneConfig declares the desired records and reconcile behavior for a zone.
type ZoneConfig struct {
	// ZoneName is the domain name of the zone. Normalized to have a trailing dot
	// during parsing.
	ZoneName string `json:"zone_name"`

	// DNS provider for this zone (namespace=dns.providers inline_key=name).
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	// Desired records, in generic RR form (Name/TTL/Type/Data). Structured
	// Caddyfile directives are normalized into RRs at parse time.
	Records []libdns.RR `json:"records,omitempty"`

	// How aggressively to reconcile. One of "report", "upsert", or "mirror".
	// Required for now (no default) so operators make a conscious safety
	// choice; will default to "upsert" once the module stabilizes.
	SyncMode string `json:"sync_mode,omitempty"`

	// Default TTL applied to records that don't specify one. 0 means "let the
	// DNS provider decide".
	DefaultTTL caddy.Duration `json:"default_ttl,omitempty"`

	// Protect selects the built-in protection policies that shield records from
	// modification or deletion. Omitted or ["default"] means all default
	// protections: caddy-acme, caddy-ech, apex-ns, and soa. ["none"] disables
	// built-in protections, and ["all"] enables every known built-in policy.
	Protect []string `json:"protect,omitempty"`

	// ProtectRRsets holds structured [type, name...] matchers. Records whose
	// RRset matches any matcher are never modified or deleted, regardless of
	// sync_mode. A type of "*" matches any type.
	ProtectRRsets [][]string `json:"protect_rrsets,omitempty"`

	provider        zoneProvider
	mutator         mutator
	protectPolicies map[string]bool
}

// zoneProvider is the set of libdns capabilities required to reconcile a zone.
type zoneProvider interface {
	libdns.RecordGetter
	libdns.RecordSetter
	libdns.RecordDeleter
}

// mutator applies the computed set/delete changes to a zone. This seam lets
// the initial implementation call libdns directly while leaving room for a
// future event-emitting implementation without restructuring the sync engine.
type mutator interface {
	apply(ctx context.Context, zone string, set, del []libdns.Record) error
}

// directMutator is the MVP implementation: it calls libdns DeleteRecords and
// SetRecords directly on the provider.
type directMutator struct{ provider zoneProvider }

func (m directMutator) apply(ctx context.Context, zone string, set, del []libdns.Record) error {
	if len(del) > 0 {
		if _, err := m.provider.DeleteRecords(ctx, zone, del); err != nil {
			return fmt.Errorf("deleting records: %w", err)
		}
	}
	if len(set) > 0 {
		if _, err := m.provider.SetRecords(ctx, zone, set); err != nil {
			return fmt.Errorf("setting records: %w", err)
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns_zone",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision calls Validate to normalize the app configuration, then loads and
// provisions each zone's DNS provider.
func (a *App) Provision(ctx caddy.Context) (err error) {
	a.ctx, a.cancel = caddy.NewContext(ctx)
	// If provisioning fails, Caddy never calls Start/Stop on this instance, so
	// cancel the child context here rather than leaking it until the parent
	// context is cancelled.
	defer func() {
		if err != nil {
			a.cancel()
		}
	}()
	a.logger = ctx.Logger(a)
	a.wg = &sync.WaitGroup{}

	// Don't normalize in place to avoid incidentally applying the caddy
	// replacer to fields recursively. Don't cache in case the public config
	// changes between calls to Validate and Provision.
	zones, err := a.getNormalizedZones()
	if err != nil {
		return err
	}
	a.normalizedZones = zones

	for _, zc := range a.normalizedZones {
		val, err := ctx.LoadModule(zc, "DNSProviderRaw")
		if err != nil {
			return fmt.Errorf("zone %q: loading DNS provider module: %w", zc.ZoneName, err)
		}
		prov, err := asZoneProvider(val)
		if err != nil {
			return fmt.Errorf("zone %q: %w", zc.ZoneName, err)
		}
		zc.provider = prov
		zc.mutator = directMutator{provider: prov}
	}
	return nil
}

// Validate checks the app configuration for validity, including the sync mode
// name, protection filters, TTLs, placeholder replacement on supported fields,
// and record data. It returns an error if any validation fails. Note: Validate
// cannot load or type-check provider modules because provider loading requires a
// caddy.Context, which is only passed to Provision.
func (a *App) Validate() error {
	_, err := a.getNormalizedZones()
	return err
}

func (a *App) getNormalizedZones() (zones []*ZoneConfig, err error) {
	if len(a.Zones) == 0 {
		return nil, fmt.Errorf("no zones configured")
	}
	normalizedZones := make([]*ZoneConfig, 0, len(a.Zones))

	repl := caddy.NewReplacer()

	for i, zc := range a.Zones {
		if zc == nil {
			return nil, fmt.Errorf("zone at index %d: empty configuration", i)
		}

		// Work on a copy so validation never mutates the caller's config.
		cp := *zc
		zc = &cp

		// Normalize the zone name and validate it.
		zc.ZoneName = normalizeZoneName(repl.ReplaceAll(zc.ZoneName, ""))
		if err := validateZoneName(zc.ZoneName); err != nil {
			return nil, fmt.Errorf("zone %q (%d): %w", zc.ZoneName, i, err)
		}

		// sync_mode is required for now.
		switch zc.SyncMode {
		case syncModeReport, syncModeUpsert, syncModeMirror:
			// ok
		case "":
			return nil, fmt.Errorf("zone %q: sync_mode is required (one of %q, %q, %q)",
				zc.ZoneName, syncModeReport, syncModeUpsert, syncModeMirror)
		default:
			return nil, fmt.Errorf("zone %q: invalid sync_mode %q (must be one of %q, %q, %q)",
				zc.ZoneName, zc.SyncMode, syncModeReport, syncModeUpsert, syncModeMirror)
		}

		if err := validateTTL(time.Duration(zc.DefaultTTL), "default_ttl"); err != nil {
			return nil, fmt.Errorf("zone %q: %w", zc.ZoneName, err)
		}

		policies, err := normalizeProtectPolicies(zc.Protect)
		if err != nil {
			return nil, fmt.Errorf("zone %q: %w", zc.ZoneName, err)
		}
		zc.protectPolicies = policies

		protectRRsets, err := normalizeProtectRRsets(zc.ProtectRRsets, repl, zc.ZoneName)
		if err != nil {
			return nil, fmt.Errorf("zone %q: %w", zc.ZoneName, err)
		}
		zc.ProtectRRsets = protectRRsets

		// Apply the replacer + default TTL to each record, then validate by
		// parsing the RDATA.
		records, err := normalizeRecords(zc.Records, repl, zc.DefaultTTL, zc.ZoneName)
		if err != nil {
			return nil, fmt.Errorf("zone %q: %w", zc.ZoneName, err)
		}
		zc.Records = records

		// DNS provider is required. Checked here (rather than in Provision) so
		// that `caddy validate` reports it, and so the duplicate detection
		// below never has to compare an absent provider config.
		if len(zc.DNSProviderRaw) == 0 {
			return nil, fmt.Errorf("zone %q: a DNS provider is required", zc.ZoneName)
		}

		// Check for declared records that are also protected by the ignore filter.
		// This is a configuration error.
		for j := range zc.Records {
			if ok, err := zc.isProtected(zc.Records[j], zc.ZoneName); err != nil {
				return nil, fmt.Errorf("zone %q: %w", zc.ZoneName, err)
			} else if ok {
				return nil, fmt.Errorf("zone %q: record %q is both declared and protected; remove the record declaration or the protection",
					zc.ZoneName, zc.Records[j].Name+" "+zc.Records[j].Type)
			}
		}

		normalizedZones = append(normalizedZones, zc)
	}

	// Detect duplicates among normalized zones. n^2 time complexity is acceptable
	// for a small number of zones (up to 100 or so).
	for i, zi := range normalizedZones {
		for j, zj := range normalizedZones[i+1:] {
			ok, err := jsonEqual(zi.DNSProviderRaw, zj.DNSProviderRaw)
			if err != nil {
				return nil, fmt.Errorf("failed to compare zone provider config: %w", err)
			}
			if zi.ZoneName == zj.ZoneName && ok {
				// Only name the provider module; the raw provider config may
				// contain secrets (e.g. API tokens) that must not end up in
				// logs or error output.
				return nil, fmt.Errorf("duplicate zone found at indexes %d and %d. zone name: %q, provider: %s", i, i+j+1, zi.ZoneName, providerName(zi.DNSProviderRaw))
			}
		}
	}

	return normalizedZones, nil
}

func normalizeProtectRRsets(matchers [][]string, repl *caddy.Replacer, zone string) ([][]string, error) {
	out := make([][]string, 0, len(matchers))
	for i, matcher := range matchers {
		if len(matcher) < 2 {
			return nil, fmt.Errorf("protect_rrsets[%d]: requires a type and at least one name", i)
		}

		typ := strings.ToUpper(strings.TrimSpace(repl.ReplaceAll(matcher[0], "")))
		if typ == "" {
			return nil, fmt.Errorf("protect_rrsets[%d]: type is required", i)
		}
		if typ != "*" && !isValidRRTypeToken(typ) {
			return nil, fmt.Errorf("protect_rrsets[%d]: invalid type %q", i, matcher[0])
		}

		normalized := make([]string, 0, len(matcher))
		normalized = append(normalized, typ)
		for j, name := range matcher[1:] {
			name = strings.TrimSpace(repl.ReplaceAll(name, ""))
			if name == "" {
				return nil, fmt.Errorf("protect_rrsets[%d][%d]: name is required", i, j+1)
			}
			if err := validateOwnerName(name, zone, fmt.Sprintf("protect_rrsets[%d][%d]", i, j+1)); err != nil {
				return nil, err
			}
			normalized = append(normalized, name)
		}
		out = append(out, normalized)
	}
	return out, nil
}

func isValidRRTypeToken(typ string) bool {
	for _, r := range typ {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// providerName extracts the provider module name from a raw provider config
// for use in error messages. It deliberately returns only the name: the rest
// of the config may contain secrets such as API tokens.
func providerName(raw json.RawMessage) string {
	var v struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Name == "" {
		return "(unknown)"
	}
	return v.Name
}

// jsonEqual compares two JSON-encoded byte slices for equality.
func jsonEqual(a, b []byte) (bool, error) {
	var ua, ub any
	erra := json.Unmarshal(a, &ua)
	errb := json.Unmarshal(b, &ub)
	if erra != nil || errb != nil {
		return false, fmt.Errorf("failed to unmarshal JSON: %w", errors.Join(erra, errb))
	}
	return reflect.DeepEqual(ua, ub), nil
}

// asZoneProvider type-asserts a loaded module to the required libdns
// interfaces, returning a descriptive error naming any missing interface.
func asZoneProvider(val any) (zoneProvider, error) {
	if zp, ok := val.(zoneProvider); ok {
		return zp, nil
	}
	var missing []string
	if _, ok := val.(libdns.RecordGetter); !ok {
		missing = append(missing, "RecordGetter")
	}
	if _, ok := val.(libdns.RecordSetter); !ok {
		missing = append(missing, "RecordSetter")
	}
	if _, ok := val.(libdns.RecordDeleter); !ok {
		missing = append(missing, "RecordDeleter")
	}
	return nil, fmt.Errorf("DNS provider %T does not implement required libdns interface(s): %s",
		val, strings.Join(missing, ", "))
}

// See App.Start and App.Stop in sync.go
// normalizeZoneName canonicalizes a zone name for both provider calls and
// duplicate detection: it trims surrounding whitespace, lowercases (DNS names
// are case-insensitive per RFC 4343), and ensures exactly one trailing dot —
// the canonical FQDN form most libdns providers expect.
func normalizeZoneName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return name
	}
	return strings.TrimRight(name, ".") + "."
}

// Interface guards
var (
	_ caddy.Validator   = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
	_ mutator           = directMutator{}
)
