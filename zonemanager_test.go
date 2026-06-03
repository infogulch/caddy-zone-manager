package zonemanager

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
)

// getterOnly implements only libdns.RecordGetter, to exercise
// asZoneProvider's reporting of a partially-implemented provider.
type getterOnly struct{}

func (getterOnly) GetRecords(context.Context, string) ([]libdns.Record, error) {
	return nil, nil
}

// rr is a terse constructor for a libdns.RR; ttl is in seconds (0 = unset).
func rr(name, typ, data string, ttlSecs int) libdns.RR {
	return libdns.RR{
		Name: name,
		Type: typ,
		Data: data,
		TTL:  time.Duration(ttlSecs) * time.Second,
	}
}

func recs(rs ...libdns.RR) []libdns.Record {
	out := make([]libdns.Record, len(rs))
	for i := range rs {
		out[i] = rs[i]
	}
	return out
}

func TestNormalizeZoneName(t *testing.T) {
	cases := map[string]string{
		"example.com":     "example.com.",
		"example.com.":    "example.com.",
		"example.com..":   "example.com.",
		"Example.COM":     "example.com.",
		"  example.com  ": "example.com.",
		"":                "",
	}
	for in, want := range cases {
		if got := normalizeZoneName(in); got != want {
			t.Errorf("normalizeZoneName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTTL(t *testing.T) {
	ok := map[string]time.Duration{
		"300":   300 * time.Second,
		"3600":  3600 * time.Second,
		"0":     0,
		"1h":    time.Hour,
		"90m":   90 * time.Minute,
		"1h30m": 90 * time.Minute,
	}
	for in, want := range ok {
		got, err := parseTTL(in)
		if err != nil {
			t.Errorf("parseTTL(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseTTL(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"-5", "abc", "-1h", "", "1h2", "300ms", "1.5s"} {
		if _, err := parseTTL(bad); err == nil {
			t.Errorf("parseTTL(%q) expected error, got nil", bad)
		}
	}
}

func TestAsZoneProvider_MissingInterfaces(t *testing.T) {
	// The mock implements all three required interfaces.
	if _, err := asZoneProvider(&mockProvider{}); err != nil {
		t.Fatalf("mockProvider should satisfy zoneProvider: %v", err)
	}

	// A value implementing none of the required interfaces: the error must
	// name all three.
	_, err := asZoneProvider(struct{}{})
	if err == nil {
		t.Fatal("expected error for type implementing no libdns interfaces")
	}
	for _, want := range []string{"RecordGetter", "RecordSetter", "RecordDeleter"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention missing %q", err, want)
		}
	}

	// A partial implementation (RecordGetter only): the error must name the
	// missing interfaces but not the implemented one.
	_, err = asZoneProvider(getterOnly{})
	if err == nil {
		t.Fatal("expected error for type implementing only RecordGetter")
	}
	for _, want := range []string{"RecordSetter", "RecordDeleter"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "RecordGetter") {
		t.Errorf("error %q should not list RecordGetter (it is implemented)", err)
	}
}

func TestNormalizeRecords_DefaultTTLAndValidation(t *testing.T) {
	records := []libdns.RR{
		{Name: "@", Type: "a", Data: "203.0.113.10"},                          // ttl filled, type upcased
		{Name: "www", Type: "A", Data: "203.0.113.11", TTL: 60 * time.Second}, // explicit ttl kept
	}
	defaultTTL := caddy.Duration(3600 * time.Second)

	records, err := normalizeRecords(records, caddy.NewReplacer(), defaultTTL, "example.com.")
	if err != nil {
		t.Fatalf("normalizeRecords: %v", err)
	}
	if records[0].TTL != 3600*time.Second {
		t.Errorf("record 0 ttl = %v, want default 3600s", records[0].TTL)
	}
	if records[0].Type != "A" {
		t.Errorf("record 0 type = %q, want uppercased A", records[0].Type)
	}
	if records[1].TTL != 60*time.Second {
		t.Errorf("record 1 ttl = %v, want explicit 60s", records[1].TTL)
	}

	badRecords := []libdns.RR{{Name: "@", Type: "A", Data: "not-an-ip"}}
	if _, err := normalizeRecords(badRecords, caddy.NewReplacer(), defaultTTL, "example.com."); err == nil {
		t.Fatal("expected validation error for malformed A record")
	}

	maxTTLRecord := []libdns.RR{{Name: "@", Type: "A", Data: "203.0.113.10", TTL: time.Duration(maxDNSTTLSeconds) * time.Second}}
	if _, err := normalizeRecords(maxTTLRecord, caddy.NewReplacer(), 0, "example.com."); err != nil {
		t.Fatalf("max DNS TTL should be accepted: %v", err)
	}
	overMaxTTLRecord := []libdns.RR{{Name: "@", Type: "A", Data: "203.0.113.10", TTL: time.Duration(maxDNSTTLSeconds+1) * time.Second}}
	if _, err := normalizeRecords(overMaxTTLRecord, caddy.NewReplacer(), 0, "example.com."); err == nil {
		t.Fatal("expected validation error for TTL greater than max DNS TTL")
	}
}

func TestRRSetEqual(t *testing.T) {
	cases := []struct {
		name             string
		desired, current []libdns.Record
		want             bool
	}{
		{
			name:    "ttl zero ignored",
			desired: recs(rr("@", "A", "203.0.113.10", 0)),
			current: recs(rr("@", "A", "203.0.113.10", 300)),
			want:    true,
		},
		{
			name:    "explicit ttl mismatch",
			desired: recs(rr("@", "A", "203.0.113.10", 60)),
			current: recs(rr("@", "A", "203.0.113.10", 300)),
			want:    false,
		},
		{
			name:    "same multivalue different order",
			desired: recs(rr("@", "A", "203.0.113.10", 0), rr("@", "A", "203.0.113.11", 0)),
			current: recs(rr("@", "A", "203.0.113.11", 300), rr("@", "A", "203.0.113.10", 300)),
			want:    true,
		},
		{
			name:    "different data",
			desired: recs(rr("@", "A", "203.0.113.10", 0)),
			current: recs(rr("@", "A", "203.0.113.99", 0)),
			want:    false,
		},
		{
			name:    "different cardinality",
			desired: recs(rr("@", "A", "203.0.113.10", 0)),
			current: recs(rr("@", "A", "203.0.113.10", 0), rr("@", "A", "203.0.113.11", 0)),
			want:    false,
		},
	}
	for _, tc := range cases {
		if got := rrsetEqual(tc.desired, tc.current); got != tc.want {
			t.Errorf("%s: rrsetEqual = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCanonicalData(t *testing.T) {
	cases := []struct {
		name string
		rr   libdns.RR
		want string
	}{
		{"aaaa expanded compresses", rr("@", "AAAA", "2001:0db8:0000:0000:0000:0000:0000:0001", 0), "2001:db8::1"},
		{"aaaa already canonical", rr("@", "AAAA", "2001:db8::1", 0), "2001:db8::1"},
		{"caa quoting normalized", rr("@", "CAA", "0 issue letsencrypt.org", 0), `0 issue "letsencrypt.org"`},
		{"mx whitespace normalized", rr("@", "MX", "10   mail.example.com.", 0), "10 mail.example.com."},
		// HTTPS/SVCB are passed through untouched (only trimmed) to avoid
		// non-deterministic SvcParams re-serialization.
		{"https passed through trimmed", rr("@", "HTTPS", `  1 . ech=AEX+DQ alpn="h2,h3"  `, 0), `1 . ech=AEX+DQ alpn="h2,h3"`},
		// Unparseable RDATA falls back to the trimmed raw value.
		{"unparseable falls back", rr("@", "A", "  not-an-ip  ", 0), "not-an-ip"},
	}
	for _, tc := range cases {
		if got := canonicalData(tc.rr); got != tc.want {
			t.Errorf("%s: canonicalData = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestMatchProtectRRset(t *testing.T) {
	zone := "example.com."
	cases := []struct {
		name    string
		matcher []string
		rr      libdns.RR
		want    bool
	}{
		{"type and name match", []string{"TXT", "_dmarc"}, rr("_dmarc", "TXT", "v=DMARC1", 0), true},
		{"type mismatch", []string{"TXT", "_dmarc"}, rr("_dmarc", "A", "1.2.3.4", 0), false},
		{"name mismatch", []string{"TXT", "_dmarc"}, rr("other", "TXT", "x", 0), false},
		{"wildcard type", []string{"*", "_dmarc"}, rr("_dmarc", "A", "1.2.3.4", 0), true},
		{"case-insensitive type", []string{"txt", "_dmarc"}, rr("_dmarc", "TXT", "x", 0), true},
		{"multiple names", []string{"A", "a", "b"}, rr("b", "A", "1.2.3.4", 0), true},
	}
	for _, tc := range cases {
		if got := matchProtectRRset(tc.matcher, tc.rr, zone); got != tc.want {
			t.Errorf("%s: matchProtectRRset = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBuiltInProtections(t *testing.T) {
	zone := "example.com."
	if !isCaddyACME(rr("_acme-challenge", "TXT", "tok", 0), zone) {
		t.Error("_acme-challenge TXT should match caddy-acme")
	}
	if !isCaddyACME(rr("_acme-challenge.www", "TXT", "tok", 0), zone) {
		t.Error("_acme-challenge.www TXT should match caddy-acme")
	}
	if !isCaddyACME(rr("_acme-challenge", "CNAME", "x.acme-dns.io.", 0), zone) {
		t.Error("_acme-challenge CNAME should match caddy-acme")
	}
	if isCaddyACME(rr("acme-challenge", "TXT", "x", 0), zone) {
		t.Error("acme-challenge without underscore should not match caddy-acme")
	}

	if !isCaddyECH(rr("@", "HTTPS", `2 . ech=AEX+DQ alpn="h2,h3"`, 0)) {
		t.Error("HTTPS ech= should match caddy-ech")
	}
	if !isCaddyECH(rr("www", "SVCB", "1 . ech=AAAA", 0)) {
		t.Error("SVCB ech= should match caddy-ech")
	}
	if isCaddyECH(rr("@", "HTTPS", `1 . alpn="h2,h3"`, 0)) {
		t.Error("HTTPS without ech= should not match caddy-ech")
	}

	if !isApexNS(rr("@", "NS", "ns1.example.net.", 0), zone) {
		t.Error("apex NS should match apex-ns")
	}
	if isApexNS(rr("child", "NS", "ns1.child.example.", 0), zone) {
		t.Error("delegation NS should not match apex-ns")
	}
	if !isSOA(rr("@", "SOA", "ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 3600", 0)) {
		t.Error("SOA should match soa")
	}
}

func TestNormalizeZones_DuplicateRejected(t *testing.T) {
	m := &mockProvider{providerTTL: 300 * time.Second}
	cases := map[string][]*ZoneConfig{
		"exact match": {
			newZoneManager(m, syncModeUpsert),
			newZoneManager(m, syncModeUpsert),
		},
		"normalized match": {
			named(newZoneManager(m, syncModeUpsert), "example.com"),
			named(newZoneManager(m, syncModeUpsert), "example.com."),
		},
	}
	for name, zones := range cases {
		app, _ := testApp()
		app.Zones = zones
		_, err := app.getNormalizedZones()
		if err == nil {
			t.Errorf("%s: expected error for duplicate zone block, got nil", name)
		}
	}
}

func TestNormalizeZones_DuplicateNameDifferentProviderAccepted(t *testing.T) {
	m1 := &mockProvider{}
	m2 := &mockProvider{Params: []string{"hello"}}
	app, _ := testApp()
	app.Zones = []*ZoneConfig{
		newZoneManager(m1, syncModeUpsert),
		newZoneManager(m2, syncModeUpsert),
	}
	_, err := app.getNormalizedZones()
	if err != nil {
		t.Fatalf("expected no error for zone blocks with same name but different provider, got error: %v", err)
	}
}
