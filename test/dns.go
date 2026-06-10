package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var errTimeout = errors.New("deadline exceeded")

// qmeta identifies the owner of a dns_query run-log line.
type qmeta struct {
	caseName  string // owning case, or "preflight" / "cleanup"
	assertion string // present | absent | discovery
	attempt   int    // 1-based poll iteration
}

// dnsClient performs all DNS traffic for the run. Every query — assertion
// polls, NS discovery, pre-flight and cleanup checks — flows through query(),
// which emits one dns_query run-log line per attempt, so the run log is a
// complete record of every DNS exchange.
//
// By default assertions query exactly one nameserver, chosen during
// pre-flight and pinned for the whole run. The harness validates the
// module's mutations against the provider, not propagation across the
// provider's NS fleet — and stickiness keeps the observed state monotonic:
// alternating between replicas that are ahead/behind in propagation could
// make a record asserted present in one case appear absent in the next.
// --all-nameservers restores strict all-server unanimity. Polling uses a
// flat interval (no backoff): it keeps the attempt timeline in the run log
// trivial to read.
type dnsClient struct {
	servers  []string // pinned assertion target(s); set during pre-flight 0.3
	timeout  time.Duration
	interval time.Duration
	log      *runLog
	udp      *dns.Client
	tcp      *dns.Client
}

func newDNSClient(log *runLog, timeout, interval time.Duration) *dnsClient {
	return &dnsClient{
		timeout:  timeout,
		interval: interval,
		log:      log,
		udp:      &dns.Client{Net: "udp", Timeout: 5 * time.Second},
		tcp:      &dns.Client{Net: "tcp", Timeout: 5 * time.Second},
	}
}

// query performs a single DNS query (UDP with TCP fallback on truncation) and
// logs one dns_query line. eval classifies a successful exchange as
// "match" / "mismatch" / "absent"; transport errors are logged as "error".
//
// Assertions send RD=0, as is proper for authoritative servers. Note that
// Akamai-fronted Linode nameservers serve per-RRset cached answers with
// counting-down TTLs that can be stale for up to the record's original TTL
// regardless of the RD bit; the harness defends against that by embedding
// the per-run nonce in record names so each run queries names that have
// never been cached, and by keeping the test zone's SOA default TTL low.
func (d *dnsClient) query(ctx context.Context, m qmeta, server, fqdn string, qtype uint16, rd bool, eval func(*dns.Msg) string) (*dns.Msg, string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = rd
	start := time.Now()
	resp, _, err := d.udp.ExchangeContext(ctx, msg, server)
	if err == nil && resp.Truncated {
		resp, _, err = d.tcp.ExchangeContext(ctx, msg, server)
	}
	rtt := time.Since(start)

	ev := map[string]any{
		"event":      "dns_query",
		"case":       m.caseName,
		"assertion":  m.assertion,
		"attempt":    m.attempt,
		"nameserver": server,
		"question":   map[string]string{"name": fqdn, "type": dns.TypeToString[qtype]},
		"rtt_ms":     rtt.Milliseconds(),
	}
	outcome := "error"
	if err != nil {
		ev["error"] = err.Error()
	} else {
		ev["rcode"] = dns.RcodeToString[resp.Rcode]
		if len(resp.Answer) > 0 {
			ev["answer"] = rrStrings(resp.Answer)
		}
		if len(resp.Ns) > 0 {
			ev["authority"] = rrStrings(resp.Ns)
		}
		outcome = eval(resp)
	}
	ev["outcome"] = outcome
	d.log.event(ev)
	return resp, outcome, err
}

// AssertPresent polls the pinned nameserver(s) until every one of them
// answers with a record of qtype at fqdn matching wantData (canonicalized;
// presence-only when empty) and wantTTL (only when non-zero), or the deadline
// expires or ctx is cancelled. For NS and SOA queries, matching records in
// the Authority section also count (delegation referrals).
func (d *dnsClient) AssertPresent(ctx context.Context, caseName, fqdn string, qtype uint16, wantData string, wantTTL uint32) error {
	var wantRData string
	if wantData != "" {
		var err error
		wantRData, err = canonicalRData(fqdn, qtype, wantData)
		if err != nil {
			return fmt.Errorf("cannot canonicalize expected data %q: %w", wantData, err)
		}
	}
	deadline := time.Now().Add(d.timeout)
	for attempt := 1; ; attempt++ {
		satisfied := true
		var last string
		for _, server := range d.servers {
			_, outcome, err := d.query(ctx, qmeta{caseName, "present", attempt}, server, fqdn, qtype, false, func(resp *dns.Msg) string {
				if presentIn(resp, fqdn, qtype, wantRData, wantTTL) {
					return "match"
				}
				if resp.Rcode == dns.RcodeNameError ||
					(resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && len(candidates(resp, fqdn, qtype)) == 0) {
					return "absent"
				}
				return "mismatch"
			})
			if err != nil {
				satisfied = false
				last = err.Error()
			} else if outcome != "match" {
				satisfied = false
				last = fmt.Sprintf("%s from %s", outcome, server)
			}
		}
		if satisfied {
			return nil
		}
		if err := sleepOrDone(ctx, deadline, d.interval); err != nil {
			return fmt.Errorf("not present after %d attempts (%s): %w", attempt, last, err)
		}
	}
}

// AssertAbsent polls until the record is absent on every pinned nameserver.
// Without unwantedData, absence means NXDOMAIN or NODATA. With unwantedData,
// a NOERROR answer is also accepted as long as no record of the queried type
// carries that RDATA after canonical normalization (the rest of the RRset may
// legitimately remain).
func (d *dnsClient) AssertAbsent(ctx context.Context, caseName, fqdn string, qtype uint16, unwantedData string) error {
	var unwantedRData string
	if unwantedData != "" {
		var err error
		unwantedRData, err = canonicalRData(fqdn, qtype, unwantedData)
		if err != nil {
			return fmt.Errorf("cannot canonicalize unwanted data %q: %w", unwantedData, err)
		}
	}
	deadline := time.Now().Add(d.timeout)
	for attempt := 1; ; attempt++ {
		satisfied := true
		var last string
		for _, server := range d.servers {
			_, outcome, err := d.query(ctx, qmeta{caseName, "absent", attempt}, server, fqdn, qtype, false, func(resp *dns.Msg) string {
				switch {
				case resp.Rcode == dns.RcodeNameError:
					return "absent" // NXDOMAIN
				case resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0:
					return "absent" // NODATA
				case resp.Rcode == dns.RcodeSuccess && unwantedRData != "":
					for _, rr := range candidates(resp, fqdn, qtype) {
						if rdataOf(rr) == unwantedRData {
							return "mismatch" // the unwanted RDATA is still there
						}
					}
					return "match" // RRset answers, but without the unwanted RDATA
				default:
					return "mismatch"
				}
			})
			if err != nil {
				satisfied = false
				last = err.Error()
			} else if outcome != "absent" && outcome != "match" {
				satisfied = false
				last = fmt.Sprintf("still present on %s", server)
			}
		}
		if satisfied {
			return nil
		}
		if err := sleepOrDone(ctx, deadline, d.interval); err != nil {
			return fmt.Errorf("not absent after %d attempts (%s): %w", attempt, last, err)
		}
	}
}

// rrTarget is a (fqdn, qtype) pair the run will create or assert on.
type rrTarget struct {
	fqdn  string
	qtype uint16
}

// checkZoneEmpty verifies the zone holds no test records (pre-flight step
// 0.4, re-used by cleanup step 3) in two tiers:
//
//   - Non-apex targets (every name the case files touch) are hard-asserted
//     absent with the normal polling deadline. These names carry the per-run
//     nonce, so no edge cache entry can exist for them and a leftover answer
//     means a genuinely dirty zone.
//   - Apex RRsets (A, AAAA, MX, TXT, CNAME, CAA, SRV, plus any apex case
//     targets) cannot be renamed per-run, and the Akamai-fronted nameservers
//     may serve them stale for up to their original TTL after deletion, so a
//     positive answer is only a warning. Provider-side emptiness is enforced
//     authoritatively by pre-flight 0.5 (would_delete == 0).
func (d *dnsClient) checkZoneEmpty(ctx context.Context, caseName, zoneFQDN string, extra []rrTarget) error {
	seen := make(map[rrTarget]bool)
	var apex, named []rrTarget
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeCNAME, dns.TypeCAA, dns.TypeSRV} {
		t := rrTarget{zoneFQDN, qt}
		apex = append(apex, t)
		seen[t] = true
	}
	for _, t := range extra {
		if seen[t] {
			continue
		}
		seen[t] = true
		if t.fqdn == zoneFQDN {
			apex = append(apex, t)
		} else {
			named = append(named, t)
		}
	}
	for _, t := range apex {
		for _, server := range d.servers {
			// Warn-only, so a dropped UDP packet must not fail the run:
			// retry transient transport errors a few times, then warn.
			var outcome string
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				_, outcome, err = d.query(ctx, qmeta{caseName, "absent", attempt}, server, t.fqdn, t.qtype, false, func(resp *dns.Msg) string {
					if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
						return "absent"
					}
					return "mismatch"
				})
				if err == nil || ctx.Err() != nil {
					break
				}
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil || outcome != "absent" {
				detail := "answered (possibly stale edge cache; provider state is verified separately)"
				if err != nil {
					detail = "query failed: " + err.Error()
				}
				fmt.Printf("    warning: apex %s on %s: %s\n", dns.TypeToString[t.qtype], server, detail)
				d.log.event(map[string]any{"event": "apex_warning", "case": caseName, "type": dns.TypeToString[t.qtype], "nameserver": server, "detail": detail})
			}
		}
	}
	for _, t := range named {
		if err := d.AssertAbsent(ctx, caseName, t.fqdn, t.qtype, ""); err != nil {
			return fmt.Errorf("%s %s: %w", t.fqdn, dns.TypeToString[t.qtype], err)
		}
	}
	return nil
}

// discoverNameservers resolves the zone's NS records via the given recursive
// resolvers, then resolves each NS hostname to its A/AAAA address(es). All
// queries are logged as discovery dns_query lines.
func (d *dnsClient) discoverNameservers(ctx context.Context, zoneFQDN string, resolvers []string) ([]string, error) {
	evalNonEmpty := func(resp *dns.Msg) string {
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return "match"
		}
		if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
			return "absent"
		}
		return "mismatch"
	}

	var nsNames []string
	var resolver string
	var lastErr error
	for i, res := range resolvers {
		resp, _, err := d.query(ctx, qmeta{"preflight", "discovery", i + 1}, res, zoneFQDN, dns.TypeNS, true, evalNonEmpty)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range resp.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}
		if len(nsNames) > 0 {
			resolver = res
			break
		}
	}
	if len(nsNames) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("NS discovery for %s failed: %w", zoneFQDN, lastErr)
		}
		return nil, fmt.Errorf("no NS records found for %s", zoneFQDN)
	}
	sort.Strings(nsNames)

	var servers []string
	for _, host := range nsNames {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resp, _, err := d.query(ctx, qmeta{"preflight", "discovery", 1}, resolver, dns.Fqdn(host), qt, true, evalNonEmpty)
			if err != nil {
				continue
			}
			for _, rr := range resp.Answer {
				switch a := rr.(type) {
				case *dns.A:
					servers = append(servers, net.JoinHostPort(a.A.String(), "53"))
				case *dns.AAAA:
					servers = append(servers, net.JoinHostPort(a.AAAA.String(), "53"))
				}
			}
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("none of the NS hosts for %s resolved to an address: %v", zoneFQDN, nsNames)
	}
	return servers, nil
}

// systemResolvers returns recursive resolver addresses for NS discovery:
// the system's resolv.conf when available, otherwise well-known publics.
func systemResolvers() []string {
	if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
		out := make([]string, 0, len(cc.Servers))
		for _, s := range cc.Servers {
			out = append(out, net.JoinHostPort(s, cc.Port))
		}
		return out
	}
	return []string{"8.8.8.8:53", "1.1.1.1:53"}
}

// normalizeServer ensures a nameserver address carries a port (default 53).
func normalizeServer(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}

// candidates returns the records of qtype owned by fqdn that count toward a
// presence check: Answer-section records, plus Authority-section records for
// NS and SOA queries only (delegation referrals and SOA surfacing there).
func candidates(resp *dns.Msg, fqdn string, qtype uint16) []dns.RR {
	src := resp.Answer
	if qtype == dns.TypeNS || qtype == dns.TypeSOA {
		src = append(append([]dns.RR(nil), resp.Answer...), resp.Ns...)
	}
	var out []dns.RR
	for _, rr := range src {
		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, fqdn) {
			out = append(out, rr)
		}
	}
	return out
}

// presentIn reports whether the response satisfies a presence assertion.
func presentIn(resp *dns.Msg, fqdn string, qtype uint16, wantRData string, wantTTL uint32) bool {
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range candidates(resp, fqdn, qtype) {
		if wantRData != "" && rdataOf(rr) != wantRData {
			continue
		}
		if wantTTL != 0 && rr.Header().Ttl != wantTTL {
			continue
		}
		return true
	}
	return false
}

// rdataOf extracts a record's RDATA in presentation format by stripping the
// header prefix from RR.String().
func rdataOf(rr dns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// canonicalRData round-trips RDATA through miekg/dns (parse -> serialize),
// matching the canonicalization caddy-zone-manager applies internally.
func canonicalRData(fqdn string, qtype uint16, data string) (string, error) {
	rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN %s %s", fqdn, dns.TypeToString[qtype], data))
	if err != nil {
		return "", err
	}
	if rr == nil {
		return "", fmt.Errorf("data parsed to no record")
	}
	return rdataOf(rr), nil
}

func rrStrings(rrs []dns.RR) []string {
	out := make([]string, len(rrs))
	for i, rr := range rrs {
		out[i] = rr.String()
	}
	return out
}

// sleepOrDone waits one poll interval, returning ctx.Err() on cancellation or
// errTimeout when another interval would overrun the deadline.
func sleepOrDone(ctx context.Context, deadline time.Time, interval time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if time.Now().Add(interval).After(deadline) {
		return errTimeout
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(interval):
		return nil
	}
}
