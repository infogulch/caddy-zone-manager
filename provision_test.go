package zonemanager

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
)

// newTestContext returns a caddy.Context suitable for unit-testing Provision.
// Its cfg is nil, which Caddy explicitly tolerates in tests: Context.Logger
// falls back to a dev logger, and Context.LoadModule resolves modules from the
// global registry without needing a running config.
func newTestContext(t *testing.T) caddy.Context {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return ctx
}

func provZone(zoneName string, mode string, records ...libdns.RR) *ZoneConfig {
	return &ZoneConfig{
		ZoneName:       zoneName,
		DNSProviderRaw: json.RawMessage(`{"name":"mock"}`),
		SyncMode:       mode,
		Records:        records,
	}
}

func TestProvision_Success(t *testing.T) {
	app := &App{Zones: []*ZoneConfig{
		provZone("example.com", syncModeUpsert, rr("@", "a", "203.0.113.10", 0)),
	}}
	if err := app.Provision(newTestContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Provision validates onto internal copies, leaving app.Zones untouched.
	zc := app.normalizedZones[0]
	if zc.ZoneName != "example.com." {
		t.Errorf("zoneName = %q, want example.com.", zc.ZoneName)
	}
	if zc.provider == nil {
		t.Error("provider not wired")
	}
	if zc.mutator == nil {
		t.Error("mutator not wired")
	}
	for _, policy := range defaultProtectPolicies {
		if !zc.protectPolicies[policy] {
			t.Errorf("default protect policy %q was not enabled", policy)
		}
	}
	if zc.Records[0].Type != "A" {
		t.Errorf("record type = %q, want normalized A", zc.Records[0].Type)
	}
}

func TestProvision_Errors(t *testing.T) {
	cases := map[string]*App{
		"missing sync_mode": {Zones: []*ZoneConfig{
			provZone("example.com", ""),
		}},
		"invalid sync_mode": {Zones: []*ZoneConfig{
			provZone("example.com", "bogus"),
		}},
		"missing provider": {Zones: []*ZoneConfig{
			{SyncMode: syncModeUpsert},
		}},
		"invalid zone name": {Zones: []*ZoneConfig{
			provZone("bad..example", syncModeUpsert),
		}},
		"bad record data": {Zones: []*ZoneConfig{
			provZone("example.com", syncModeUpsert, rr("@", "A", "not-an-ip", 0)),
		}},
		"out-of-zone record name": {Zones: []*ZoneConfig{
			provZone("example.com", syncModeUpsert, rr("other.example.", "A", "203.0.113.10", 0)),
		}},
		"invalid record name": {Zones: []*ZoneConfig{
			provZone("example.com", syncModeUpsert, rr("bad..name", "A", "203.0.113.10", 0)),
		}},
		"fractional record ttl": {Zones: []*ZoneConfig{
			provZone("example.com", syncModeUpsert, libdns.RR{Name: "@", Type: "A", Data: "203.0.113.10", TTL: 500 * time.Millisecond}),
		}},
		"negative default_ttl": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.DefaultTTL = caddy.Duration(-1)
				return zc
			}(),
		}},
		"fractional default_ttl": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.DefaultTTL = caddy.Duration(500 * time.Millisecond)
				return zc
			}(),
		}},
		"oversized default_ttl": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.DefaultTTL = caddy.Duration(time.Duration(maxDNSTTLSeconds+1) * time.Second)
				return zc
			}(),
		}},
		"bad protect policy": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.Protect = []string{"bogus"}
				return zc
			}(),
		}},
		"mixed protect keyword": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.Protect = []string{"default", "soa"}
				return zc
			}(),
		}},
		"protect_rrset too few fields": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.ProtectRRsets = [][]string{{"TXT"}}
				return zc
			}(),
		}},
		"protect_rrset empty type": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.ProtectRRsets = [][]string{{"", "_dmarc"}}
				return zc
			}(),
		}},
		"protect_rrset empty name": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.ProtectRRsets = [][]string{{"TXT", ""}}
				return zc
			}(),
		}},
		"protect_rrset invalid type token": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.ProtectRRsets = [][]string{{"BAD-TYPE", "@"}}
				return zc
			}(),
		}},
		"protect_rrset invalid name": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.ProtectRRsets = [][]string{{"TXT", "bad..name"}}
				return zc
			}(),
		}},
		"protect_rrset out-of-zone name": {Zones: []*ZoneConfig{
			func() *ZoneConfig {
				zc := provZone("example.com", syncModeUpsert)
				zc.ProtectRRsets = [][]string{{"TXT", "other.example."}}
				return zc
			}(),
		}},
		"no zones": {Zones: []*ZoneConfig{}},
		"zones normalizing to same name": {Zones: []*ZoneConfig{
			provZone("example.com", syncModeUpsert),
			provZone("example.com.", syncModeUpsert),
		}},
	}
	for name, app := range cases {
		t.Run(name, func(t *testing.T) {
			if err := app.Provision(newTestContext(t)); err == nil {
				t.Errorf("expected Provision error for %q, got nil", name)
			}
		})
	}
}

func TestProvision_DefaultTTLApplied(t *testing.T) {
	zc := provZone("example.com", syncModeUpsert, rr("@", "A", "203.0.113.10", 0))
	zc.DefaultTTL = caddy.Duration(3600e9) // 3600s in ns
	app := &App{Zones: []*ZoneConfig{zc}}
	if err := app.Provision(newTestContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got := app.normalizedZones[0].Records[0].TTL.Seconds(); got != 3600 {
		t.Errorf("record TTL = %vs, want 3600s (from default_ttl)", got)
	}
}

func TestProvision_DoesNotMutateOriginalConfig(t *testing.T) {
	// Validation works on copies, so the caller's ZoneConfig (including its
	// Records backing array) must be left exactly as provided.
	zc := provZone("Example.COM", syncModeUpsert, rr("@", "a", "203.0.113.10", 0))
	zc.DefaultTTL = caddy.Duration(3600e9)
	app := &App{Zones: []*ZoneConfig{zc}}
	if err := app.Provision(newTestContext(t)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if app.Zones[0].ZoneName != "Example.COM" {
		t.Errorf("original ZoneName mutated: got %q, want %q", app.Zones[0].ZoneName, "Example.COM")
	}
	orig := app.Zones[0].Records[0]
	if orig.Type != "a" || orig.TTL != 0 {
		t.Errorf("original record mutated: got type=%q ttl=%v, want type=%q ttl=0", orig.Type, orig.TTL, "a")
	}
}

func TestValidate_NilZone(t *testing.T) {
	// A nil zone entry (reachable via native JSON like {"zones":[null]}) must
	// produce a clean error rather than a nil-pointer panic.
	app := &App{Zones: []*ZoneConfig{nil}}
	if err := app.Validate(); err == nil {
		t.Fatal("expected error for nil zone config, got nil")
	}
}

func TestProvision_DeclaredRecordMatchingProtectionErrors(t *testing.T) {
	// Explicit RRset protection overlapping a declared record.
	zc := provZone("example.com", syncModeMirror, rr("_dmarc", "TXT", "v=DMARC1; p=none", 0))
	zc.ProtectRRsets = [][]string{{"TXT", "_dmarc"}}
	app := &App{Zones: []*ZoneConfig{zc}}
	if err := app.Provision(newTestContext(t)); err == nil {
		t.Fatal("expected error: record both declared and matched by protect_rrset")
	}

	// Default caddy-acme protection overlapping a declared _acme-challenge record.
	zc2 := provZone("example.com", syncModeMirror, rr("_acme-challenge", "TXT", "tok", 0))
	app2 := &App{Zones: []*ZoneConfig{zc2}}
	if err := app2.Provision(newTestContext(t)); err == nil {
		t.Fatal("expected error: declared record matched by caddy-acme protection")
	}

	// With built-in protections disabled, the same _acme-challenge declaration is allowed.
	zc3 := provZone("example.com", syncModeMirror, rr("_acme-challenge", "TXT", "tok", 0))
	zc3.Protect = []string{"none"}
	app3 := &App{Zones: []*ZoneConfig{zc3}}
	if err := app3.Provision(newTestContext(t)); err != nil {
		t.Fatalf("unexpected error with protect none: %v", err)
	}
}
