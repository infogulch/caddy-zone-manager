package zonemanager

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/libdns/libdns"
)

// parseInto runs parseApp on input and unmarshals the resulting app JSON.
func parseInto(t *testing.T, input string) (*App, error) {
	t.Helper()
	got, err := parseApp(caddyfile.NewTestDispenser(input), nil)
	if err != nil {
		return nil, err
	}
	app := new(App)
	if err := json.Unmarshal(got.(httpcaddyfile.App).Value, app); err != nil {
		t.Fatalf("unmarshal app JSON: %v", err)
	}
	return app, nil
}

func TestParseApp_Records(t *testing.T) {
	app, err := parseInto(t, `
		dns_zone example.com {
			provider mock
			sync_mode upsert
			records {
				a     @   203.0.113.10
				aaaa  @   2001:db8::1        300
				cname www example.com.
				ns    @   ns1.example.com.
				txt   @   "v=spf1 -all"
				caa   @   0 issue "letsencrypt.org"
				mx    @   10 mail.example.com.   3600
				srv   _sip._tcp 10 5 5060 sip.example.com.
				rr    _443._tcp 3600 TLSA "3 1 1 ABCD"
			}
		}`)
	if err != nil {
		t.Fatalf("parseApp: %v", err)
	}
	zc := app.Zones[0]
	if zc == nil {
		t.Fatal("zone example.com missing")
	}
	if zc.SyncMode != "upsert" {
		t.Errorf("sync_mode = %q, want upsert", zc.SyncMode)
	}
	if string(zc.DNSProviderRaw) != `{"name":"mock"}` {
		t.Errorf("dns_provider = %s, want {\"name\":\"mock\"}", zc.DNSProviderRaw)
	}

	want := []libdns.RR{
		{Name: "@", Type: "A", Data: "203.0.113.10"},
		{Name: "@", Type: "AAAA", Data: "2001:db8::1", TTL: 300 * time.Second},
		{Name: "www", Type: "CNAME", Data: "example.com."},
		{Name: "@", Type: "NS", Data: "ns1.example.com."},
		{Name: "@", Type: "TXT", Data: "v=spf1 -all"},
		{Name: "@", Type: "CAA", Data: `0 issue "letsencrypt.org"`},
		{Name: "@", Type: "MX", Data: "10 mail.example.com.", TTL: 3600 * time.Second},
		{Name: "_sip._tcp", Type: "SRV", Data: "10 5 5060 sip.example.com."},
		{Name: "_443._tcp", Type: "TLSA", Data: "3 1 1 ABCD", TTL: 3600 * time.Second},
	}
	if !reflect.DeepEqual(zc.Records, want) {
		t.Errorf("records mismatch:\n got %#v\nwant %#v", zc.Records, want)
	}
}

func TestParseApp_MultilineBlocks(t *testing.T) {
	app, err := parseInto(t, `
		dns_zone example.com {
			provider mock
			sync_mode mirror
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
		}`)
	if err != nil {
		t.Fatalf("parseApp: %v", err)
	}
	want := []libdns.RR{
		{Name: "@", Type: "MX", Data: "10 mail.example.com.", TTL: 3600 * time.Second},
		{Name: "_sip._tcp", Type: "SRV", Data: "10 5 5060 sip.example.com."},
	}
	if got := app.Zones[0].Records; !reflect.DeepEqual(got, want) {
		t.Errorf("records mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseApp_ProtectionAndDefaults(t *testing.T) {
	app, err := parseInto(t, `
		dns_zone example.com {
			provider mock
			sync_mode mirror
			default_ttl 1h
			protect caddy-acme apex-ns soa
			protect_rrset TXT _dmarc verify
			protect_rrset MX @
			records {
				a @ 203.0.113.10
			}
		}`)
	if err != nil {
		t.Fatalf("parseApp: %v", err)
	}
	zc := app.Zones[0]
	if zc.DefaultTTL != caddy.Duration(time.Hour) {
		t.Errorf("default_ttl = %v, want 1h", time.Duration(zc.DefaultTTL))
	}
	wantProtect := []string{"caddy-acme", "apex-ns", "soa"}
	if !reflect.DeepEqual(zc.Protect, wantProtect) {
		t.Errorf("protect = %v, want %v", zc.Protect, wantProtect)
	}
	wantRRsets := [][]string{{"TXT", "_dmarc", "verify"}, {"MX", "@"}}
	if !reflect.DeepEqual(zc.ProtectRRsets, wantRRsets) {
		t.Errorf("protect_rrsets = %v, want %v", zc.ProtectRRsets, wantRRsets)
	}
}

func TestParseApp_MultipleZonesAggregate(t *testing.T) {
	first, err := parseApp(caddyfile.NewTestDispenser(`
		dns_zone example.com {
			provider mock
			sync_mode upsert
			records {
				a @ 203.0.113.10
			}
		}`), nil)
	if err != nil {
		t.Fatalf("first parseApp: %v", err)
	}
	second, err := parseApp(caddyfile.NewTestDispenser(`
		dns_zone other.example {
			provider mock
			sync_mode upsert
			records {
				a @ 203.0.113.20
			}
		}`), first)
	if err != nil {
		t.Fatalf("second parseApp: %v", err)
	}
	app := new(App)
	if err := json.Unmarshal(second.(httpcaddyfile.App).Value, app); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(app.Zones) != 2 {
		t.Fatalf("got %d zones, want 2: %v", len(app.Zones), app.Zones)
	}
	if len(app.Zones) != 2 {
		t.Errorf("both zones should be present: %v", app.Zones)
	}
}

// Zone deduplication doesn't happen until the app is normalized
func TestParseApp_DuplicateZonesAccepted(t *testing.T) {
	first, err := parseApp(caddyfile.NewTestDispenser(`
		dns_zone example.com {
			provider mock
			sync_mode upsert
			records {
				a @ 203.0.113.10
			}
		}`), nil)
	if err != nil {
		t.Fatalf("first parseApp: %v", err)
	}
	_, err = parseApp(caddyfile.NewTestDispenser(`
		dns_zone example.com {
			provider mock
			sync_mode mirror
			records {
				a @ 203.0.113.20
			}
		}`), first)
	if err != nil {
		t.Fatalf("second parseApp: %v", err)
	}
}

func TestParseApp_SameZoneDifferentProvidersAccepted(t *testing.T) {
	first, err := parseApp(caddyfile.NewTestDispenser(`
		dns_zone example.com {
			provider mock
			sync_mode upsert
			records {
				a @ 203.0.113.10
			}
		}`), nil)
	if err != nil {
		t.Fatalf("first parseApp: %v", err)
	}
	_, err = parseApp(caddyfile.NewTestDispenser(`
		dns_zone example.com {
			provider mock extra_arg
			sync_mode mirror
			records {
				a @ 203.0.113.20
			}
		}`), first)
	if err != nil {
		t.Fatalf("second parseApp: %v", err)
	}
}

func TestParseApp_EmptyRecordsBlock(t *testing.T) {
	app, err := parseInto(t, `
		dns_zone example.com {
			provider mock
			sync_mode upsert
			records { }
		}`)
	if err != nil {
		t.Fatalf("parseApp: %v", err)
	}
	if got := app.Zones[0].Records; len(got) != 0 {
		t.Errorf("expected empty records slice, got %v", got)
	}
}

func TestParseApp_EmptyRecordsBlockMultiline(t *testing.T) {
	app, err := parseInto(t, `
		dns_zone example.com {
			provider mock
			sync_mode upsert
			records {
			}
		}`)
	if err != nil {
		t.Fatalf("parseApp: %v", err)
	}
	if got := app.Zones[0].Records; len(got) != 0 {
		t.Errorf("expected empty records slice, got %v", got)
	}
}

func TestParseApp_Errors(t *testing.T) {
	cases := map[string]string{
		"missing zone arg": `dns_zone {
			provider mock
		}`,
		"unknown directive": `dns_zone example.com {
			frobnicate yes
		}`,
		"unknown record type": `dns_zone example.com {
			records {
				wat @ value
			}
		}`,
		"missing records block": `dns_zone example.com {
			provider mock
			sync_mode upsert
		}`,
		"records without block": `dns_zone example.com {
			records
		}`,
		"records with trailing args": `dns_zone example.com {
			records a @ 203.0.113.10
		}`,
		"a too few args": `dns_zone example.com {
			records {
				a @
			}
		}`,
		"rr wrong arity": `dns_zone example.com {
			records {
				rr @ 3600 TXT
			}
		}`,
		"bad ttl": `dns_zone example.com {
			records {
				a @ 203.0.113.10 notattl
			}
		}`,
		"fractional record ttl": `dns_zone example.com {
			records {
				a @ 203.0.113.10 500ms
			}
		}`,
		"default_ttl extra arg": `dns_zone example.com {
			default_ttl 1h extra
		}`,
		"fractional default_ttl": `dns_zone example.com {
			default_ttl 500ms
		}`,
		"protect no args": `dns_zone example.com {
			protect
		}`,
		"duplicate provider": `dns_zone example.com {
			provider mock
			provider mock
		}`,
		"duplicate sync_mode": `dns_zone example.com {
			sync_mode report
			sync_mode upsert
		}`,
		"duplicate default_ttl": `dns_zone example.com {
			default_ttl 1h
			default_ttl 2h
		}`,
		"duplicate protect": `dns_zone example.com {
			protect default
			protect none
		}`,
		"protect_rrset too few args": `dns_zone example.com {
			protect_rrset TXT
		}`,
		"mx block extra arg": `dns_zone example.com {
			records {
				mx @ {
					preference 10 extra
					target mail.example.com.
				}
			}
		}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseApp(caddyfile.NewTestDispenser(input), nil); err == nil {
				t.Errorf("expected error for %q, got nil", name)
			}
		})
	}
}
