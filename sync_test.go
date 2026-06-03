package zonemanager

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&mockProvider{})
}

// mockProvider is an in-memory libdns provider used by tests. It implements
// RecordGetter/Setter/Deleter with the documented libdns semantics, and is
// also a registered Caddy module (dns.providers.mock) so the Caddyfile parser
// and provider loading can be exercised.
type mockProvider struct {
	Params []string `json:"params,omitempty"`

	mu   sync.Mutex
	recs []libdns.RR

	setCalls    int
	deleteCalls int

	// providerTTL, when > 0, is assigned to records whose input TTL is 0, to
	// simulate a provider applying its own default TTL. This lets tests verify
	// the TTL-0 idempotency rule.
	providerTTL time.Duration

	// getCalls counts GetRecords invocations.
	getCalls int

	// failGets, when > 0, makes the first failGets GetRecords calls return
	// getErr (decrementing each call). This simulates a provider that is briefly
	// unreachable at boot and lets tests exercise the sync retry path. Use a
	// large value for "always fail".
	failGets int
	getErr   error
}

func (*mockProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.mock",
		New: func() caddy.Module { return new(mockProvider) },
	}
}

func (m *mockProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		m.Params = d.RemainingArgs()
		for n := d.Nesting(); d.NextBlock(n); {
		}
	}
	return nil
}

func (a *App) syncAll() []error { return a.syncZones(a.normalizedZones) }

func mockKey(rr libdns.RR, zone string) string {
	return strings.ToLower(libdns.AbsoluteName(rr.Name, zone)) + "|" + strings.ToUpper(rr.Type)
}

func mockID(rr libdns.RR, zone string) string {
	return mockKey(rr, zone) + "|" + strings.TrimSpace(rr.Data)
}

func (m *mockProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls++
	if m.failGets > 0 {
		m.failGets--
		err := m.getErr
		if err == nil {
			err = errors.New("mock: GetRecords failed")
		}
		return nil, err
	}
	out := make([]libdns.Record, 0, len(m.recs))
	for _, rr := range m.recs {
		out = append(out, rr)
	}
	return out, nil
}

func (m *mockProvider) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCalls++

	replace := make(map[string]bool)
	for _, r := range recs {
		replace[mockKey(r.RR(), zone)] = true
	}
	var kept []libdns.RR
	for _, rr := range m.recs {
		if !replace[mockKey(rr, zone)] {
			kept = append(kept, rr)
		}
	}
	for _, r := range recs {
		rr := r.RR()
		if rr.TTL == 0 && m.providerTTL > 0 {
			rr.TTL = m.providerTTL
		}
		kept = append(kept, rr)
	}
	m.recs = kept
	return recs, nil
}

func (m *mockProvider) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++

	del := make(map[string]bool)
	for _, r := range recs {
		del[mockID(r.RR(), zone)] = true
	}
	var kept []libdns.RR
	for _, rr := range m.recs {
		if !del[mockID(rr, zone)] {
			kept = append(kept, rr)
		}
	}
	m.recs = kept
	return recs, nil
}

// dataFor returns the sorted RDATA values currently stored for an RRset.
func (m *mockProvider) dataFor(zone, name, typ string) []libdns.RR {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := strings.ToLower(libdns.AbsoluteName(name, zone)) + "|" + strings.ToUpper(typ)
	var out []libdns.RR
	for _, rr := range m.recs {
		if mockKey(rr, zone) == want {
			out = append(out, rr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Data < out[j].Data
	})
	return out
}

// ttlFor returns the TTL stored for a specific record (by name/type/data).
func (m *mockProvider) ttlFor(zone, name, typ, data string) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := strings.ToLower(libdns.AbsoluteName(name, zone)) + "|" + strings.ToUpper(typ)
	for _, rr := range m.recs {
		if mockKey(rr, zone) == want && strings.TrimSpace(rr.Data) == data {
			return rr.TTL, true
		}
	}
	return 0, false
}

// newZoneManager builds a provisioned-equivalent ZoneConfig wired to m.
func newZoneManager(m *mockProvider, mode string, records ...libdns.RR) *ZoneConfig {
	jsonm, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return &ZoneConfig{
		ZoneName:        "example.com.",
		SyncMode:        mode,
		Records:         records,
		DNSProviderRaw:  jsonm,
		provider:        m,
		mutator:         directMutator{provider: m},
		protectPolicies: policySet(defaultProtectPolicies...),
	}
}

func testApp() (*App, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cctx := caddy.Context{Context: ctx}
	return &App{logger: zap.NewNop(), ctx: cctx}, cancel
}

func normalizedTestApp(t *testing.T, zones ...*ZoneConfig) (*App, context.CancelFunc) {
	var err error
	app, cancel := testApp()
	app.Zones = zones
	app.normalizedZones, err = app.getNormalizedZones()
	if err != nil {
		cancel()
		t.Fatalf("normalizeZones: %v", err)
	}
	return app, cancel
}

// named overrides the zone name on a ZoneConfig, for tests that wire several
// zones into one App and need to tell them apart.
func named(zc *ZoneConfig, name string) *ZoneConfig {
	zc.ZoneName = name
	return zc
}

func TestSync_CreateOnEmptyZone(t *testing.T) {
	m := &mockProvider{}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "A", "203.0.113.10", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if got := m.dataFor("example.com.", "@", "A"); len(got) != 1 || got[0].Data != "203.0.113.10" {
		t.Fatalf("A @ = %v, want [203.0.113.10]", got)
	}
	if m.setCalls != 1 {
		t.Fatalf("setCalls = %d, want 1", m.setCalls)
	}
}

func TestSync_Idempotent_TTLZeroIgnored(t *testing.T) {
	m := &mockProvider{providerTTL: 300 * time.Second}

	// First sync creates the record
	app1, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "A", "203.0.113.10", 0)),
	)
	if errs := app1.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("first syncAll: %v", errs)
	}
	// check that the record was created with non-zero provider TTL
	if got := m.dataFor("example.com.", "@", "A"); len(got) != 1 || got[0].TTL != 300*time.Second {
		t.Fatalf("record TTL = %s, want 300", got[0])
	}

	// Second sync with the same desired state (TTL 0) must be a no-op even
	// though the provider now reports TTL=300.
	app2, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "A", "203.0.113.10", 0)),
	)
	if errs := app2.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("second syncAll: %v", errs)
	}
	if m.setCalls != 1 {
		t.Fatalf("setCalls = %d, want 1 (second sync should be a no-op)", m.setCalls)
	}
}

func TestSync_Idempotent_EquivalentRDATANotRewritten(t *testing.T) {
	// The provider reports RDATA in non-canonical but equivalent presentation
	// forms: an AAAA address in fully-expanded form (config uses the compressed
	// form) and a CAA record with an unquoted value (config uses the canonical
	// quoted form). A re-sync must recognize these as already up to date and
	// perform no writes.
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "@", Type: "AAAA", Data: "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{Name: "@", Type: "CAA", Data: "0 issue letsencrypt.org"},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "AAAA", "2001:db8::1", 0),
		rr("@", "CAA", `0 issue "letsencrypt.org"`, 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if m.setCalls != 0 {
		t.Fatalf("setCalls = %d, want 0 (equivalent RDATA must not be rewritten)", m.setCalls)
	}
}

func TestSync_Idempotent_TXTNotRewritten(t *testing.T) {
	// TXT is opaque to libdns: Parse() round-trips the presentation form
	// verbatim (it does NOT normalize quoting), so canonicalData only trims
	// surrounding whitespace. The guarantee this test locks in is therefore
	// narrow but important: when a provider echoes TXT data in the same form it
	// was declared in (the common case, e.g. SPF/DMARC), a re-sync performs no
	// writes. The provider here returns the values with surrounding whitespace
	// to exercise the TrimSpace normalization, and a multi-value RRset to verify
	// set-equality across TXT members.
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "@", Type: "TXT", Data: "  v=spf1 -all  "},
		{Name: "_dmarc", Type: "TXT", Data: "v=DMARC1; p=none"},
		{Name: "@", Type: "TXT", Data: "google-site-verification=abc123"},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "TXT", "v=spf1 -all", 0),
		rr("@", "TXT", "google-site-verification=abc123", 0),
		rr("_dmarc", "TXT", "v=DMARC1; p=none", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if m.setCalls != 0 {
		t.Fatalf("setCalls = %d, want 0 (identically-formatted TXT must not be rewritten)", m.setCalls)
	}
}

func TestSync_UpdateOnlyDifferingRRsets(t *testing.T) {
	m := &mockProvider{providerTTL: 300 * time.Second}
	m.recs = []libdns.RR{
		{Name: "@", Type: "A", Data: "203.0.113.10", TTL: 300 * time.Second},
		{Name: "@", Type: "TXT", Data: "keepme", TTL: 300 * time.Second},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "A", "203.0.113.99", 0), // changed
		rr("@", "TXT", "keepme", 0),     // unchanged
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if got := m.dataFor("example.com.", "@", "A"); len(got) != 1 || got[0].Data != "203.0.113.99" {
		t.Fatalf("A @ = %v, want [203.0.113.99]", got)
	}
	if got := m.dataFor("example.com.", "@", "TXT"); len(got) != 1 || got[0].Data != "keepme" {
		t.Fatalf("TXT @ = %v, want [keepme]", got)
	}
	if m.setCalls != 1 {
		t.Fatalf("setCalls = %d, want 1 (only the A RRset changed)", m.setCalls)
	}
}

func TestSync_UpdatePreservesUnchangedSiblingTTL(t *testing.T) {
	// Existing RRset has two A records with a distinct, non-default TTL (999s).
	m := &mockProvider{providerTTL: 300 * time.Second}
	m.recs = []libdns.RR{
		{Name: "@", Type: "A", Data: "203.0.113.10", TTL: 999 * time.Second},
		{Name: "@", Type: "A", Data: "203.0.113.11", TTL: 999 * time.Second},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		// Desired keeps .10 (ttl 0), drops .11, adds .12 (ttl 0) — the RRset changes.
		rr("@", "A", "203.0.113.10", 0),
		rr("@", "A", "203.0.113.12", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	// .10 was unchanged: its 999s TTL must be preserved, not reset to the
	// provider default (300s).
	if ttl, ok := m.ttlFor("example.com.", "@", "A", "203.0.113.10"); !ok || ttl != 999*time.Second {
		t.Errorf(".10 TTL = %v (present=%v), want preserved 999s", ttl, ok)
	}
	// .12 is new with desired TTL 0, so it gets the provider default (300s).
	if ttl, ok := m.ttlFor("example.com.", "@", "A", "203.0.113.12"); !ok || ttl != 300*time.Second {
		t.Errorf(".12 TTL = %v (present=%v), want provider default 300s", ttl, ok)
	}
	// .11 was dropped from the declared RRset.
	if _, ok := m.ttlFor("example.com.", "@", "A", "203.0.113.11"); ok {
		t.Error(".11 should have been removed")
	}
}

func TestSync_DeclaredHTTPSOverlappingLiveECHIsLeftAlone(t *testing.T) {
	// The live HTTPS record carries an ECH "ech=" param (published by Caddy),
	// so it is protected. The user also declares an HTTPS record at the same
	// name without ech= (which passes provision, since the declared record
	// isn't protected). At sync time the RRset must be left untouched so we
	// don't clobber Caddy's ech=.
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "@", Type: "HTTPS", Data: `2 . alpn="h2,h3" ech=AEX+DQ`},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "HTTPS", `1 . alpn="h2,h3"`, 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if m.setCalls != 0 {
		t.Errorf("setCalls = %d, want 0 (protected RRset must not be overwritten)", m.setCalls)
	}
	got := m.dataFor("example.com.", "@", "HTTPS")
	if len(got) != 1 || got[0].Data != `2 . alpn="h2,h3" ech=AEX+DQ` {
		t.Errorf("live HTTPS record = %v, want unchanged (ech= preserved)", got)
	}
}

func TestSync_ReportMakesNoChanges(t *testing.T) {
	m := &mockProvider{}
	m.recs = []libdns.RR{{Name: "@", Type: "A", Data: "203.0.113.10"}}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeReport,
		rr("@", "A", "203.0.113.99", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if m.setCalls != 0 || m.deleteCalls != 0 {
		t.Fatalf("report mutated: setCalls=%d deleteCalls=%d, want 0/0", m.setCalls, m.deleteCalls)
	}
	if got := m.dataFor("example.com.", "@", "A"); len(got) != 1 || got[0].Data != "203.0.113.10" {
		t.Fatalf("A @ = %v, want unchanged [203.0.113.10]", got)
	}
}

func TestSync_UpsertNeverDeletesUndeclared(t *testing.T) {
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "@", Type: "A", Data: "203.0.113.10"},
		{Name: "old", Type: "TXT", Data: "leftover"},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeUpsert,
		rr("@", "A", "203.0.113.99", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if m.deleteCalls != 0 {
		t.Fatalf("deleteCalls = %d, want 0 in upsert", m.deleteCalls)
	}
	if got := m.dataFor("example.com.", "old", "TXT"); len(got) != 1 {
		t.Fatalf("undeclared TXT old was removed in upsert: %v", got)
	}
}

func TestSync_MirrorDeletesUndeclared(t *testing.T) {
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "@", Type: "A", Data: "203.0.113.10"},
		{Name: "old", Type: "TXT", Data: "leftover"},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeMirror,
		rr("@", "A", "203.0.113.10", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if got := m.dataFor("example.com.", "old", "TXT"); len(got) != 0 {
		t.Fatalf("undeclared TXT old should be deleted in mirror, got %v", got)
	}
	if got := m.dataFor("example.com.", "@", "A"); len(got) != 1 {
		t.Fatalf("declared A @ missing after mirror: %v", got)
	}
}

func TestSync_MirrorProtectsDefaultPolicies(t *testing.T) {
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "_acme-challenge", Type: "TXT", Data: "token"},
		{Name: "@", Type: "HTTPS", Data: `1 . ech=AEX+DQ`},
		{Name: "@", Type: "NS", Data: "ns1.example.net."},
		{Name: "@", Type: "SOA", Data: "ns1.example.net. hostmaster.example.com. 1 7200 3600 1209600 3600"},
		{Name: "old", Type: "TXT", Data: "leftover"},
	}

	app, _ := normalizedTestApp(t, newZoneManager(m, syncModeMirror,
		rr("@", "A", "203.0.113.10", 0),
	))

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if got := m.dataFor("example.com.", "_acme-challenge", "TXT"); len(got) != 1 {
		t.Fatalf("_acme-challenge TXT must be protected by caddy-acme, got %v", got)
	}
	if got := m.dataFor("example.com.", "@", "HTTPS"); len(got) != 1 {
		t.Fatalf("HTTPS ech= record must be protected by caddy-ech, got %v", got)
	}
	if got := m.dataFor("example.com.", "@", "NS"); len(got) != 1 {
		t.Fatalf("apex NS must be protected, got %v", got)
	}
	if got := m.dataFor("example.com.", "@", "SOA"); len(got) != 1 {
		t.Fatalf("SOA must be protected, got %v", got)
	}
	if got := m.dataFor("example.com.", "old", "TXT"); len(got) != 0 {
		t.Fatalf("unprotected TXT old should be deleted, got %v", got)
	}
}

func TestSync_MirrorProtectsRRsetMatcher(t *testing.T) {
	m := &mockProvider{}
	m.recs = []libdns.RR{
		{Name: "@", Type: "MX", Data: "10 mail.example.com."},
		{Name: "old", Type: "TXT", Data: "leftover"},
	}

	zc := newZoneManager(m, syncModeMirror, rr("@", "A", "203.0.113.10", 0))
	zc.ProtectRRsets = [][]string{{"MX", "@"}}

	app, _ := normalizedTestApp(t, zc)

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if got := m.dataFor("example.com.", "@", "MX"); len(got) != 1 {
		t.Fatalf("MX @ must be protected by protect_rrset, got %v", got)
	}
	if got := m.dataFor("example.com.", "old", "TXT"); len(got) != 0 {
		t.Fatalf("unprotected TXT old should be deleted, got %v", got)
	}
}

func TestSync_ProtectNoneAllowsCaddyACMEDeletion(t *testing.T) {
	m := &mockProvider{}
	m.recs = []libdns.RR{{Name: "_acme-challenge", Type: "TXT", Data: "token"}}

	zc := newZoneManager(m, syncModeMirror, rr("@", "A", "203.0.113.10", 0))
	zc.Protect = []string{"none"}
	zc.protectPolicies = policySet()

	app, _ := normalizedTestApp(t, zc)

	if errs := app.syncAll(); errors.Join(errs...) != nil {
		t.Fatalf("syncAll: %v", errs)
	}
	if got := m.dataFor("example.com.", "_acme-challenge", "TXT"); len(got) != 0 {
		t.Fatalf("with protect none, _acme-challenge should be deleted in mirror, got %v", got)
	}
}

// --- syncAll / syncLoop -----------------------------------------------------

// TestSyncAll_ReturnsPerZoneErrorsByIndex verifies the new syncAll contract:
// it returns a slice with one entry per zone, positionally aligned to a.Zones,
// holding nil for zones that synced and a non-nil error for zones that failed.
func TestSyncAll_ReturnsPerZoneErrorsByIndex(t *testing.T) {
	ok1 := &mockProvider{}
	bad := &mockProvider{failGets: 1 << 30} // always fails
	ok2 := &mockProvider{}

	app, _ := normalizedTestApp(t,
		named(newZoneManager(ok1, syncModeUpsert, rr("@", "A", "203.0.113.10", 0)), "a.example."),
		named(newZoneManager(bad, syncModeUpsert, rr("@", "A", "203.0.113.11", 0)), "b.example."),
		named(newZoneManager(ok2, syncModeUpsert, rr("@", "A", "203.0.113.12", 0)), "c.example."),
	)

	errs := app.syncAll()
	if len(errs) != len(app.Zones) {
		t.Fatalf("len(errs) = %d, want %d (one per zone)", len(errs), len(app.Zones))
	}
	if errs[0] != nil {
		t.Errorf("errs[0] = %v, want nil (zone a synced)", errs[0])
	}
	if errs[1] == nil {
		t.Errorf("errs[1] = nil, want non-nil (zone b's provider always fails)")
	}
	if errs[2] != nil {
		t.Errorf("errs[2] = %v, want nil (zone c synced)", errs[2])
	}
	// The healthy zones must have been applied despite the sibling failure.
	if got := ok1.dataFor("a.example.", "@", "A"); len(got) != 1 {
		t.Errorf("zone a not synced: %v", got)
	}
	if got := ok2.dataFor("c.example.", "@", "A"); len(got) != 1 {
		t.Errorf("zone c not synced: %v", got)
	}
}

// TestSyncLoop_ReturnsWhenAllZonesSucceed verifies the loop exits without
// scheduling a retry once every zone reports success.
func TestSyncLoop_ReturnsWhenAllZonesSucceed(t *testing.T) {
	m := &mockProvider{}

	app, _ := normalizedTestApp(t,
		newZoneManager(m, syncModeUpsert, rr("@", "A", "203.0.113.10", 0)),
	)

	done := make(chan struct{})
	go func() { app.syncLoop(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("syncLoop did not return after a fully successful sync")
	}
	if m.getCalls != 1 {
		t.Errorf("getCalls = %d, want 1 (no retry expected)", m.getCalls)
	}
}

// TestSyncLoop_ExitsOnContextCancelWhileRetrying verifies that a persistently
// failing zone keeps the loop in its retry state, and that a cancelled context
// unblocks the backoff wait and stops the loop.
func TestSyncLoop_ExitsOnContextCancelWhileRetrying(t *testing.T) {
	m := &mockProvider{failGets: 1 << 30} // always fails

	app, cancel := normalizedTestApp(t,
		newZoneManager(m, syncModeUpsert, rr("@", "A", "203.0.113.10", 0)),
	)

	// Cancel up front: the first syncAll fails, the loop logs the warning and
	// reaches the select, where the ready ctx.Done() wins over the backoff timer.
	cancel()

	done := make(chan struct{})
	go func() { app.syncLoop(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("syncLoop did not exit on context cancellation after a failure")
	}
}

// --- Start / Stop -----------------------------------------------------------

// provisionLifecycle wires the context/cancel/waitgroup fields the way
// Provision does, so Start/Stop can be exercised on an app built directly by
// the test helpers (which skip Provision).
func provisionLifecycle(app *App) {
	app.ctx, app.cancel = caddy.NewContext(app.ctx)
	app.wg = &sync.WaitGroup{}
}

// TestStop_ReturnsPromptlyWhileZoneFailing is the regression test for the
// shutdown/reload hang: a persistently failing zone parks syncLoop in its
// backoff wait, and Stop must cancel the app's own context to unblock it
// rather than waiting for Caddy to cancel the parent context (which only
// happens after Stop returns). If Stop blocked on the backoff timer it would
// take at least initialSyncBackoff (5s); the 2s guard catches the regression.
func TestStop_ReturnsPromptlyWhileZoneFailing(t *testing.T) {
	m := &mockProvider{failGets: 1 << 30} // always fails: loop parks in backoff

	app, _ := normalizedTestApp(t,
		newZoneManager(m, syncModeUpsert, rr("@", "A", "203.0.113.10", 0)),
	)
	provisionLifecycle(app)

	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- app.Stop() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return promptly; it likely blocked on the backoff wait instead of cancelling the app context")
	}
}

// TestStartStop_JoinsHealthyZone verifies the happy path: Start launches the
// sync, and Stop joins the background goroutine. Because Stop waits on the
// WaitGroup, the (mock) provider's records must be fully reconciled by the
// time Stop returns, which guards the "no overlap on quick restart" property.
func TestStartStop_JoinsHealthyZone(t *testing.T) {
	m := &mockProvider{}

	app, _ := normalizedTestApp(t,
		newZoneManager(m, syncModeUpsert, rr("@", "A", "203.0.113.10", 0)),
	)
	provisionLifecycle(app)

	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got := m.dataFor("example.com.", "@", "A"); len(got) != 1 {
		t.Errorf("zone not reconciled before Stop returned: %v", got)
	}
}

// TestSyncLoop_RetriesOnlyFailedZonesUntilRecovery verifies that the retry set
// shrinks to just the failing zones: a healthy zone is synced exactly once,
// while a flaky zone is retried until it recovers, after which the loop exits.
//
// It runs inside a synctest bubble, whose fake clock fast-forwards through the
// real initialSyncBackoff/maxSyncBackoff waits the moment every goroutine is
// blocked, so the test exercises the production backoff schedule with no
// real-time delay. Requires GOEXPERIMENT=synctest on Go 1.24.
func TestSyncLoop_RetriesOnlyFailedZonesUntilRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ok := &mockProvider{}
		flaky := &mockProvider{failGets: 2} // fails twice, succeeds on the 3rd attempt

		app, _ := normalizedTestApp(t,
			named(newZoneManager(ok, syncModeUpsert, rr("@", "A", "203.0.113.10", 0)), "ok.example."),
			named(newZoneManager(flaky, syncModeUpsert, rr("@", "A", "203.0.113.11", 0)), "flaky.example."),
		)

		done := make(chan struct{})
		go func() { app.syncLoop(); close(done) }()

		// The fake clock advances through the backoff waits automatically; if
		// the loop never converged, synctest would report a deadlock here.
		<-done

		// The healthy zone succeeds on the first pass and must not be re-queried
		// on any subsequent retry pass.
		if ok.getCalls != 1 {
			t.Errorf("ok zone getCalls = %d, want 1 (succeeded zones must not be retried)", ok.getCalls)
		}
		// The flaky zone is queried on every pass: two failures plus the recovery.
		if flaky.getCalls != 3 {
			t.Errorf("flaky zone getCalls = %d, want 3 (two failures then recovery)", flaky.getCalls)
		}
		// And it is ultimately applied.
		if got := flaky.dataFor("flaky.example.", "@", "A"); len(got) != 1 {
			t.Errorf("flaky zone not synced after recovery: %v", got)
		}
	})
}
