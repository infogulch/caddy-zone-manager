// Command test is the caddy-zone-manager integration-test harness: it
// starts Caddy, applies per-case JSON configs via `caddy reload`, and polls
// the zone's authoritative nameservers until the expected DNS state
// converges. JSON config in, real DNS out.
//
// See test/README.md for an overview, usage, and findings, and
// test/cases/README.md for the case-file schema and conventions.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const confirmEnv = "EXPECT_DOMAIN_RECORDS_WILL_BE_DESTROYED"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		caddyBin     = flag.String("caddy", "caddy", "path to the Caddy binary")
		zoneFlag     = flag.String("zone", "", "zone name, e.g. example.com (required)")
		providerFlag = flag.String("provider-json", "", "provider config as a JSON object string or @path/to/file (required)")
		configPath   = flag.String("config", "./caddy-test.json", "path the harness writes the per-step JSON config to")
		caddyLogPath = flag.String("caddy-log", "./caddy-test.log", "path for Caddy's structured JSON log")
		runLogPath   = flag.String("run-log", "./caddy-test-run.log", "path for the harness's own structured log")
		adminAddr    = flag.String("admin-addr", "localhost:2019", "Caddy Admin API address")
		dnsTimeout   = flag.Duration("dns-timeout", 60*time.Second, "maximum wait time per DNS assertion")
		dnsInterval  = flag.Duration("dns-poll-interval", 2*time.Second, "interval between DNS polls")
		nameservers  = flag.String("nameservers", "", "comma-separated authoritative NS addresses; the first entry is the sticky assertion target (default: auto-discover)")
		allNS        = flag.Bool("all-nameservers", false, "query every nameserver and require unanimity (slower, strict)")
		confirm      = flag.Bool("expect-domain-records-will-be-destroyed", false, "required confirmation that the zone is dedicated to testing")
		casesDir     = flag.String("cases", "test/cases", "directory containing the *.json case files")
	)
	flag.Parse()

	usageError := func(format string, args ...any) int {
		fmt.Fprintf(os.Stderr, "error: "+format+"\n\n", args...)
		flag.Usage()
		return 2
	}
	if *zoneFlag == "" {
		return usageError("--zone is required")
	}
	if *providerFlag == "" {
		return usageError("--provider-json is required")
	}
	if !*confirm && os.Getenv(confirmEnv) != "1" {
		return usageError("this run destroys all records in zone %q; confirm with --expect-domain-records-will-be-destroyed or %s=1", *zoneFlag, confirmEnv)
	}
	provider, err := loadProviderJSON(*providerFlag)
	if err != nil {
		return usageError("--provider-json: %v", err)
	}
	// Caddy resolves the log path relative to its own CWD and the harness
	// re-reads it; make both file paths unambiguous.
	for _, p := range []*string{configPath, caddyLogPath} {
		if abs, err := filepath.Abs(*p); err == nil {
			*p = abs
		}
	}

	zoneFQDN := normalizeZone(*zoneFlag)
	nonce := newNonce()

	rl, err := newRunLog(*runLogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot open run log: %v\n", err)
		return 1
	}
	defer func() { _ = rl.Close() }()

	fmt.Printf("=== caddy-zone-manager integration test ===\n")
	fmt.Printf("zone: %s   nonce: %s\n", zoneFQDN, nonce)
	fmt.Printf("run log: %s\ncaddy log: %s\n\n", *runLogPath, *caddyLogPath)
	rl.event(map[string]any{
		"event":             "run_start",
		"zone":              zoneFQDN,
		"nonce":             nonce,
		"admin_addr":        *adminAddr,
		"dns_timeout":       dnsTimeout.String(),
		"dns_poll_interval": dnsInterval.String(),
		"all_nameservers":   *allNS,
		"cases_dir":         *casesDir,
	})

	// Interruption: first SIGINT/SIGTERM cancels the run context (the
	// in-flight step aborts, cleanup still runs); a second one skips cleanup,
	// kills Caddy, and exits 130 immediately.
	runCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	var procHolder atomic.Pointer[caddyProcess]
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\ninterrupted — running cleanup (Ctrl+C again to abort immediately)")
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nsecond interrupt — skipping cleanup; the zone may be left dirty. Re-run the harness (cleanup is idempotent) or clean up manually.")
		if p := procHolder.Load(); p != nil {
			p.kill()
		}
		os.Exit(130)
	}()

	r := &runner{
		dns:          newDNSClient(rl, *dnsTimeout, *dnsInterval),
		log:          rl,
		zoneFQDN:     zoneFQDN,
		provider:     provider,
		configPath:   *configPath,
		caddyLogPath: *caddyLogPath,
		adminAddr:    *adminAddr,
		timeout:      *dnsTimeout,
		interval:     *dnsInterval,
	}

	// Load cases before pre-flight: the emptiness check asserts absence of
	// every (name, type) the cases will touch, not just the apex.
	cases, err := loadCases(*casesDir, nonce, zoneFQDN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading cases: %v\n", err)
		rl.event(map[string]any{"event": "case_load_error", "error": err.Error()})
		return 1
	}
	r.targets = collectCaseTargets(cases, zoneFQDN)

	preflightOK := preflight(runCtx, r, *caddyBin, *nameservers, *allNS, &procHolder)
	aborted := !preflightOK

	var results []result
	criticalFailure := false
	notRun := 0
	if preflightOK {
		fmt.Printf("\nrunning %d cases from %s\n\n", len(cases), *casesDir)
		for i := range cases {
			c := &cases[i]
			if runCtx.Err() != nil {
				notRun = len(cases) - i
				break
			}
			res := r.runCase(runCtx, c)
			results = append(results, res)
			printResult(res)
			rl.event(map[string]any{
				"event":       "case_result",
				"case":        res.Case,
				"tier":        res.Tier,
				"verdict":     res.Verdict,
				"reason":      res.Reason,
				"duration_ms": res.Duration.Milliseconds(),
			})
			if res.Verdict == verdictInterrupted {
				notRun = len(cases) - i - 1
				break
			}
			if res.Verdict == verdictFail && res.Tier == tierCritical {
				criticalFailure = true
				notRun = len(cases) - i - 1
				fmt.Println("critical failure — aborting remaining cases")
				break
			}
		}
	}

	interrupted := runCtx.Err() != nil
	cleanup(r, preflightOK, interrupted)

	criticalFailure = criticalFailure || summarize(results, notRun, *runLogPath, *caddyLogPath)

	switch {
	case interrupted:
		return 130
	case criticalFailure || aborted:
		return 1
	default:
		return 0
	}
}

// preflight runs steps 0.1–0.6. All steps are critical: the first failure
// aborts. On success the Caddy process is left running for all case files.
func preflight(ctx context.Context, r *runner, caddyBin, nameservers string, allNS bool, holder *atomic.Pointer[caddyProcess]) bool {
	step := func(num, name string, fn func() error) bool {
		if ctx.Err() != nil {
			return false
		}
		err := fn()
		ev := map[string]any{"event": "preflight", "step": num, "name": name}
		if err != nil {
			ev["error"] = err.Error()
			r.log.event(ev)
			fmt.Printf("preflight %-4s %-36s FAIL — %v\n", num, name, err)
			return false
		}
		r.log.event(ev)
		fmt.Printf("preflight %-4s %-36s ok\n", num, name)
		return true
	}

	if !step("0.1", "caddy binary works", func() error {
		_, err := caddyVersion(ctx, caddyBin)
		return err
	}) {
		return false
	}

	if !step("0.2", "admin API address is free", func() error {
		return checkAdminAddrFree(r.adminAddr)
	}) {
		return false
	}

	if !step("0.3", "select assertion nameserver", func() error {
		var servers []string
		if nameservers != "" {
			for _, s := range strings.Split(nameservers, ",") {
				if s = strings.TrimSpace(s); s != "" {
					servers = append(servers, normalizeServer(s))
				}
			}
		} else {
			var err error
			servers, err = r.dns.discoverNameservers(ctx, r.zoneFQDN, systemResolvers())
			if err != nil {
				return err
			}
		}
		if len(servers) == 0 {
			return errors.New("no nameservers available")
		}
		if !allNS {
			servers = servers[:1] // single sticky nameserver, pinned for the whole run
		}
		// Verify reachability with an SOA probe against each pinned server.
		for _, srv := range servers {
			_, _, err := r.dns.query(ctx, qmeta{"preflight", "discovery", 1}, srv, r.zoneFQDN, dns.TypeSOA, false, func(resp *dns.Msg) string {
				if resp.Rcode == dns.RcodeSuccess {
					return "match"
				}
				return "mismatch"
			})
			if err != nil {
				return fmt.Errorf("nameserver %s unreachable: %w", srv, err)
			}
		}
		r.dns.servers = servers
		r.log.event(map[string]any{"event": "nameservers_selected", "servers": servers})
		fmt.Printf("    pinned nameserver(s): %s\n", strings.Join(servers, ", "))
		return nil
	}) {
		return false
	}

	if !step("0.4", "zone is empty — DNS", func() error {
		return r.dns.checkZoneEmpty(ctx, "preflight", r.zoneFQDN, r.targets)
	}) {
		return false
	}

	// Step 0.5 deliberately disables the caddy-acme/caddy-ech policies so a
	// stale _acme-challenge.* record can't hide from would_delete.
	var offset int64
	if !step("0.5", "start caddy (empty report config)", func() error {
		offset = fileSize(r.caddyLogPath)
		az := ApplyZone{SyncMode: "report", Protect: []string{"apex-ns", "soa"}, Records: []Record{}}
		cfg, redacted, err := buildCaddyConfig(r.zoneFQDN, r.provider, az, r.adminAddr, r.caddyLogPath)
		if err != nil {
			return err
		}
		r.log.event(map[string]any{"event": "step_config", "case": "preflight", "config": json.RawMessage(redacted)})
		if err := os.WriteFile(r.configPath, cfg, 0o600); err != nil {
			return err
		}
		proc, err := startCaddy(caddyBin, r.configPath, r.adminAddr)
		if err != nil {
			return err
		}
		holder.Store(proc)
		r.caddy = proc
		return nil
	}) {
		return false
	}

	if !step("0.6", "caddy admin API reachable", func() error {
		return r.caddy.waitAdmin(ctx, 15*time.Second)
	}) {
		return false
	}

	if !step("0.5", "zone is empty — zone manager", func() error {
		fields, err := r.waitForSync(ctx, "preflight", offset)
		if err != nil {
			return err
		}
		wd, _ := fields["would_delete"].(float64)
		if int64(wd) != 0 {
			return fmt.Errorf("would_delete = %d, want 0 — zone is not empty", int64(wd))
		}
		return nil
	}) {
		return false
	}

	return true
}

// cleanup runs unconditionally on exit (only a second Ctrl+C skips it, by
// exiting the process). Failures are logged but never change the exit code.
// The zone sweep only runs when pre-flight completed: if the emptiness check
// failed, mirror-wiping unknown records would be exactly the wrong move.
func cleanup(r *runner, sweep, interrupted bool) {
	budget := 5 * time.Minute
	if interrupted {
		budget = 60 * time.Second // hard budget so cleanup cannot hang the exit
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	fmt.Println("\n=== cleanup ===")
	step := func(what string, err error) {
		ev := map[string]any{"event": "cleanup", "step": what}
		if err != nil {
			ev["error"] = err.Error()
			fmt.Printf("cleanup: %-36s FAIL — %v\n", what, err)
		} else {
			fmt.Printf("cleanup: %-36s ok\n", what)
		}
		r.log.event(ev)
	}

	if sweep && r.caddy != nil {
		// Two passes: the default policies shield records like the
		// _acme-challenge.host1 TXT planted for case 054, so a second mirror
		// with only apex-ns/soa protection sweeps what the first one spared.
		step("mirror sweep (protect default)", r.cleanupSweep(ctx, []string{"default"}))
		step("mirror sweep (protect apex-ns, soa)", r.cleanupSweep(ctx, []string{"apex-ns", "soa"}))
		step("zone is empty — DNS", r.dns.checkZoneEmpty(ctx, "cleanup", r.zoneFQDN, r.targets))
	} else if r.caddy != nil {
		fmt.Println("cleanup: skipping zone sweep (pre-flight did not complete)")
	}
	if r.caddy != nil {
		step("stop caddy", r.caddy.stop())
	}
	// The on-disk config contains the unredacted provider secret.
	if _, err := os.Stat(r.configPath); err == nil {
		step("remove config file", os.Remove(r.configPath))
	}
}

// cleanupSweep reloads an empty-mirror config with the given protect set and
// waits for the resulting sync to complete.
func (r *runner) cleanupSweep(ctx context.Context, protect []string) error {
	az := ApplyZone{SyncMode: "mirror", Protect: protect, Records: []Record{}}
	offset, err := r.applyConfig(ctx, "cleanup", az)
	if err != nil {
		return err
	}
	_, err = r.waitForSync(ctx, "cleanup", offset)
	return err
}

func printResult(res result) {
	line := fmt.Sprintf("[%-8s] %-44s %s (%.1fs)", res.Tier, res.Case, res.Verdict, res.Duration.Seconds())
	if res.Reason != "" {
		line += " — " + res.Reason
	}
	fmt.Println(line)
}

// summarize prints the final summary and reports whether any critical case failed.
func summarize(results []result, notRun int, runLogPath, caddyLogPath string) bool {
	var pass, fail, skip, intr, critFail int
	for _, res := range results {
		switch res.Verdict {
		case verdictPass:
			pass++
		case verdictFail:
			fail++
			if res.Tier == tierCritical {
				critFail++
			}
		case verdictSkip:
			skip++
		case verdictInterrupted:
			intr++
		}
	}
	fmt.Println("\n=== SUMMARY ===")
	fmt.Printf("Total: %d   PASS: %d   FAIL: %d   SKIP: %d", len(results), pass, fail, skip)
	if intr > 0 {
		fmt.Printf("   INTERRUPTED: %d", intr)
	}
	if notRun > 0 {
		fmt.Printf("   NOT RUN: %d", notRun)
	}
	fmt.Println()
	fmt.Printf("Critical failures: %d\n", critFail)
	fmt.Printf("Run log: %s\nCaddy log: %s\n", runLogPath, caddyLogPath)
	return critFail > 0
}

// loadProviderJSON parses the --provider-json value: a JSON object string, or
// @path to a file containing one.
func loadProviderJSON(arg string) (json.RawMessage, error) {
	raw := []byte(arg)
	if rest, ok := strings.CutPrefix(arg, "@"); ok {
		b, err := os.ReadFile(rest)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("must be a JSON object: %w", err)
	}
	return json.RawMessage(strings.TrimSpace(string(raw))), nil
}

// normalizeZone lowercases the zone and ensures exactly one trailing dot,
// matching the module's normalization of the "zone" log field.
func normalizeZone(zone string) string {
	return strings.ToLower(strings.TrimRight(zone, ".")) + "."
}

// newNonce returns 8 hex characters from crypto/rand, generated once per
// run. A single run-wide nonce (rather than per-use random values) keeps the
// value written via apply_zone trivially equal to the value asserted via
// expect_rr, and is easy to grep for when correlating the run log, Caddy's
// log, and the provider's audit trail. Case files reference it as the
// literal token {{nonce}}; see loadCases.
func newNonce() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b)
}
