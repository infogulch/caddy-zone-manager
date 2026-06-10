package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	tierCritical = "critical"
	tierAdvisory = "advisory"

	verdictPass        = "PASS"
	verdictFail        = "FAIL"
	verdictSkip        = "SKIP"
	verdictInterrupted = "INTERRUPTED"
)

// Case is one test case file from test/cases/*.json. The schema and case
// conventions (token substitution, cumulative state, advisory isolation)
// are documented in test/cases/README.md.
type Case struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Tier        string           `json:"tier"`
	ApplyZone   ApplyZone        `json:"apply_zone"`
	ExpectRR    []RRAssertion    `json:"expect_rr"`
	AbsentRR    []RRAssertion    `json:"absent_rr"`
	ExpectSync  map[string]int64 `json:"expect_sync"`

	File string `json:"-"`
}

// RRAssertion is one expect_rr / absent_rr entry. Data is optional
// (presence-only / NXDOMAIN-or-NODATA when empty); TTL is nanoseconds and
// asserted only when non-zero (expect_rr only).
type RRAssertion struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	TTL  int64  `json:"ttl,omitempty"`
}

// result is the recorded outcome of one executed case.
type result struct {
	Case     string
	Tier     string
	Verdict  string
	Reason   string
	Duration time.Duration
}

// loadCases reads, token-substitutes, and parses every case file in dir, in
// lexicographic order. The literal tokens {{nonce}} and {{zone}} are replaced
// on the raw bytes before unmarshaling so they work uniformly in every string
// field. {{zone}} expands to the normalized zone FQDN (lowercase, exactly one
// trailing dot) so RDATA can reference names inside the zone (CNAME/MX/SRV/NS
// targets) without the case files knowing the zone name.
func loadCases(dir, nonce, zoneFQDN string) ([]Case, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no case files found in %s", dir)
	}
	sort.Strings(paths)
	cases := make([]Case, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = bytes.ReplaceAll(raw, []byte("{{nonce}}"), []byte(nonce))
		raw = bytes.ReplaceAll(raw, []byte("{{zone}}"), []byte(zoneFQDN))
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if c.Name == "" {
			c.Name = strings.TrimSuffix(filepath.Base(path), ".json")
		}
		if c.Tier == "" {
			c.Tier = tierCritical
		}
		if c.Tier != tierCritical && c.Tier != tierAdvisory {
			return nil, fmt.Errorf("%s: invalid tier %q", path, c.Tier)
		}
		c.File = path
		cases = append(cases, c)
	}
	return cases, nil
}

// runLog writes the harness's structured log as JSON lines.
type runLog struct {
	mu sync.Mutex
	f  *os.File
}

func newRunLog(path string) (*runLog, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &runLog{f: f}, nil
}

// event writes one JSON-lines entry, adding a timestamp.
func (l *runLog) event(fields map[string]any) {
	if l == nil || l.f == nil {
		return
	}
	fields["ts"] = time.Now().Format(time.RFC3339Nano)
	b, err := json.Marshal(fields)
	if err != nil {
		b = fmt.Appendf(nil, `{"event":"log_marshal_error","error":%q}`, err.Error())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

func (l *runLog) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}

// runner executes test cases against the running Caddy process.
type runner struct {
	caddy        *caddyProcess
	dns          *dnsClient
	log          *runLog
	targets      []rrTarget // every (fqdn, qtype) the case files touch
	zoneFQDN     string     // normalized: lowercase, exactly one trailing dot
	provider     json.RawMessage
	configPath   string
	caddyLogPath string
	adminAddr    string
	timeout      time.Duration
	interval     time.Duration
}

// applyConfig records the Caddy log offset, builds and writes the per-step
// config, logs a redacted copy, and reloads Caddy. The returned offset marks
// the point before the reload, for attributing sync log lines to this step.
func (r *runner) applyConfig(ctx context.Context, caseName string, az ApplyZone) (offset int64, err error) {
	offset = fileSize(r.caddyLogPath)
	cfg, redacted, err := buildCaddyConfig(r.zoneFQDN, r.provider, az, r.adminAddr, r.caddyLogPath)
	if err != nil {
		return 0, fmt.Errorf("build config: %w", err)
	}
	r.log.event(map[string]any{"event": "step_config", "case": caseName, "config": json.RawMessage(redacted)})
	if err := os.WriteFile(r.configPath, cfg, 0o600); err != nil {
		return 0, fmt.Errorf("write config: %w", err)
	}
	out, err := r.caddy.reload(ctx, r.configPath)
	ev := map[string]any{"event": "caddy_reload", "case": caseName, "output": out}
	if err != nil {
		ev["error"] = err.Error()
	}
	r.log.event(ev)
	if err != nil {
		return 0, fmt.Errorf("caddy reload: %v: %s", err, strings.TrimSpace(out))
	}
	return offset, nil
}

// runCase executes one case: apply the config, then check expect_sync,
// expect_rr, and absent_rr in that order.
func (r *runner) runCase(ctx context.Context, c *Case) result {
	start := time.Now()
	res := func(verdict, reason string) result {
		return result{Case: c.Name, Tier: c.Tier, Verdict: verdict, Reason: reason, Duration: time.Since(start)}
	}
	// fail converts an assertion failure into the final verdict: INTERRUPTED
	// when the run context was cancelled; SKIP when an advisory case failed
	// while the provider was reporting sync errors (unsupported, not broken);
	// FAIL otherwise, with any provider error attached.
	fail := func(offset int64, reason string) result {
		if ctx.Err() != nil {
			return res(verdictInterrupted, reason)
		}
		if failures := scanSyncFailures(r.caddyLogPath, offset, r.zoneFQDN); len(failures) > 0 {
			providerErr := failures[len(failures)-1]
			if c.Tier == tierAdvisory {
				return res(verdictSkip, "provider error: "+providerErr)
			}
			reason = fmt.Sprintf("%s (zone sync failed: %s)", reason, providerErr)
		}
		return res(verdictFail, reason)
	}

	offset, err := r.applyConfig(ctx, c.Name, c.ApplyZone)
	if err != nil {
		if ctx.Err() != nil {
			return res(verdictInterrupted, err.Error())
		}
		return res(verdictFail, err.Error())
	}

	// For advisory cases only: bail out early once the sync has failed
	// persistently (the initial attempt plus at least one backoff retry),
	// since a deterministic provider rejection (e.g. an unsupported record
	// type) would otherwise stall every assertion until the full DNS timeout.
	// Cancelling syncCtx aborts the assertion polls below; fail() then turns
	// the logged provider error into a SKIP. Critical cases never bail early:
	// a transient failure (resolver blip, provider 5xx) can trip the
	// threshold, and a false-positive bail on a critical case aborts the
	// whole run, whereas waiting out the deadline lets the module's backoff
	// recover.
	syncCtx, cancelSync := context.WithCancel(ctx)
	defer cancelSync()
	if c.Tier == tierAdvisory {
		go r.cancelOnPersistentSyncFailure(syncCtx, cancelSync, c.Name, offset)
	}

	if len(c.ExpectSync) > 0 {
		fields, err := r.waitForSync(syncCtx, c.Name, offset)
		if err != nil {
			return fail(offset, "expect_sync: "+err.Error())
		}
		if err := checkSyncFields(c.ExpectSync, fields); err != nil {
			return fail(offset, "expect_sync: "+err.Error())
		}
	}

	for _, a := range c.ExpectRR {
		qtype, fqdn, err := r.assertionTarget(a)
		if err != nil {
			return res(verdictFail, fmt.Sprintf("expect_rr: %v", err))
		}
		if err := r.dns.AssertPresent(syncCtx, c.Name, fqdn, qtype, a.Data, uint32(a.TTL/Sec)); err != nil {
			return fail(offset, fmt.Sprintf("expect_rr %s %s: %v", a.Name, a.Type, err))
		}
	}
	for _, a := range c.AbsentRR {
		qtype, fqdn, err := r.assertionTarget(a)
		if err != nil {
			return res(verdictFail, fmt.Sprintf("absent_rr: %v", err))
		}
		if err := r.dns.AssertAbsent(syncCtx, c.Name, fqdn, qtype, a.Data); err != nil {
			return fail(offset, fmt.Sprintf("absent_rr %s %s: %v", a.Name, a.Type, err))
		}
	}
	return res(verdictPass, "")
}

func (r *runner) assertionTarget(a RRAssertion) (uint16, string, error) {
	qtype, ok := dns.StringToType[strings.ToUpper(a.Type)]
	if !ok {
		return 0, "", fmt.Errorf("unknown record type %q", a.Type)
	}
	return qtype, qualifyName(a.Name, r.zoneFQDN), nil
}

// collectCaseTargets returns the deduplicated (fqdn, qtype) pairs that the
// case files create or assert on, for the pre-flight/cleanup emptiness check.
// SOA everywhere and NS at the apex are excluded: those are
// provider-controlled and expected to exist in an "empty" zone.
func collectCaseTargets(cases []Case, zoneFQDN string) []rrTarget {
	seen := make(map[rrTarget]bool)
	var out []rrTarget
	add := func(name, typ string) {
		qtype, ok := dns.StringToType[strings.ToUpper(typ)]
		if !ok {
			return // unknown types are reported by the case itself
		}
		fqdn := qualifyName(name, zoneFQDN)
		if qtype == dns.TypeSOA || (qtype == dns.TypeNS && fqdn == zoneFQDN) {
			return
		}
		t := rrTarget{fqdn, qtype}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, c := range cases {
		for _, rec := range c.ApplyZone.Records {
			add(rec.Name, rec.Type)
		}
		for _, a := range c.ExpectRR {
			add(a.Name, a.Type)
		}
		for _, a := range c.AbsentRR {
			add(a.Name, a.Type)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].fqdn != out[j].fqdn {
			return out[i].fqdn < out[j].fqdn
		}
		return out[i].qtype < out[j].qtype
	})
	return out
}

// qualifyName turns a case-file record name into the FQDN to query: "@" is
// the apex, absolute names pass through, relative labels are qualified
// against the zone.
func qualifyName(name, zoneFQDN string) string {
	switch {
	case name == "" || name == "@":
		return zoneFQDN
	case strings.HasSuffix(name, "."):
		return name
	default:
		return name + "." + zoneFQDN
	}
}

// persistentSyncFailures is the number of "zone sync failed" lines after
// which an advisory case bails out early instead of waiting for the full DNS
// timeout. Two failures means the initial sync attempt and at least one
// backoff retry both failed — usually a deterministic provider rejection
// (auth, unsupported record type). Only advisory cases use this (see
// runCase): they resolve to SKIP, so a false positive from a transient error
// is cheap, while a false-positive bail on a critical case would abort the
// entire run.
const persistentSyncFailures = 2

// cancelOnPersistentSyncFailure cancels the case context once the zone sync
// has failed persistentSyncFailures times past offset. It runs alongside an
// advisory case's assertion polls and exits when the context is cancelled.
func (r *runner) cancelOnPersistentSyncFailure(ctx context.Context, cancel context.CancelFunc, caseName string, offset int64) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n := len(scanSyncFailures(r.caddyLogPath, offset, r.zoneFQDN)); n >= persistentSyncFailures {
				fmt.Printf("    zone sync failing persistently (%d attempts) — bailing early\n", n)
				r.log.event(map[string]any{"event": "sync_failure_bail", "case": caseName, "failures": n})
				cancel()
				return
			}
		}
	}
}

// waitForSync polls the Caddy log file for a "zone synced" / "zone sync
// report" line for the configured zone past the given byte offset (recorded
// before the reload — the sync runs in a background goroutine, so it may land
// arbitrarily later). "zone sync failed" lines past the same offset are
// surfaced immediately in the run log and terminal, and polling continues to
// the deadline (the module retries with backoff); advisory cases are aborted
// earlier via context cancellation (see cancelOnPersistentSyncFailure).
func (r *runner) waitForSync(ctx context.Context, caseName string, offset int64) (map[string]any, error) {
	deadline := time.Now().Add(r.timeout)
	reported := 0
	var lastFailure string
	for {
		var failures []string
		for _, line := range readLogLines(r.caddyLogPath, offset) {
			var m map[string]any
			if json.Unmarshal(line, &m) != nil {
				continue
			}
			if zone, _ := m["zone"].(string); zone != r.zoneFQDN {
				continue
			}
			switch m["msg"] {
			case "zone synced", "zone sync report":
				return m, nil
			case "zone sync failed":
				errMsg, _ := m["error"].(string)
				failures = append(failures, errMsg)
			}
		}
		for _, f := range failures[min(reported, len(failures)):] {
			fmt.Printf("    zone sync failed (module retries with backoff): %s\n", f)
			r.log.event(map[string]any{"event": "sync_failure", "case": caseName, "error": f})
			lastFailure = f
		}
		if len(failures) > reported {
			reported = len(failures)
		}
		if err := sleepOrDone(ctx, deadline, r.interval); err != nil {
			if lastFailure != "" {
				return nil, fmt.Errorf("no sync log line for zone %s: %w (last sync failure: %s)", r.zoneFQDN, err, lastFailure)
			}
			return nil, fmt.Errorf("no \"zone synced\"/\"zone sync report\" log line for zone %s past offset %d: %w", r.zoneFQDN, offset, err)
		}
	}
}

// scanSyncFailures returns the error strings of all "zone sync failed" lines
// for the zone past the given offset (one pass, no polling).
func scanSyncFailures(logPath string, offset int64, zoneFQDN string) []string {
	var failures []string
	for _, line := range readLogLines(logPath, offset) {
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if zone, _ := m["zone"].(string); zone != zoneFQDN {
			continue
		}
		if m["msg"] == "zone sync failed" {
			errMsg, _ := m["error"].(string)
			failures = append(failures, errMsg)
		}
	}
	return failures
}

// checkSyncFields verifies the declared integer fields of a sync log line.
// A key suffixed with "_min" asserts >= instead of exact equality.
func checkSyncFields(expect map[string]int64, fields map[string]any) error {
	keys := make([]string, 0, len(expect))
	for k := range expect {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want := expect[key]
		field, isMin := strings.CutSuffix(key, "_min")
		raw, ok := fields[field]
		if !ok {
			return fmt.Errorf("sync log line has no field %q", field)
		}
		num, ok := raw.(float64)
		if !ok {
			return fmt.Errorf("sync log field %q is not a number: %v", field, raw)
		}
		got := int64(num)
		if isMin {
			if got < want {
				return fmt.Errorf("%s = %d, want >= %d", field, got, want)
			}
		} else if got != want {
			return fmt.Errorf("%s = %d, want %d", field, got, want)
		}
	}
	return nil
}

// readLogLines returns the complete lines of the file past offset. A missing
// file or a trailing partial line (still being written) yields fewer lines;
// callers re-read from the same offset on the next poll.
func readLogLines(path string, offset int64) [][]byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	i := bytes.LastIndexByte(data, '\n')
	if i < 0 {
		return nil
	}
	var lines [][]byte
	for _, line := range bytes.Split(data[:i], []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

// fileSize returns the current size of the file, or 0 if it does not exist.
func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
