package zonemanager

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

const (
	initialSyncBackoff = 5 * time.Second
	maxSyncBackoff     = 5 * time.Minute

	protectCaddyACME = "caddy-acme"
	protectCaddyECH  = "caddy-ech"
	protectApexNS    = "apex-ns"
	protectSOA       = "soa"
)

var defaultProtectPolicies = []string{
	protectCaddyACME,
	protectCaddyECH,
	protectApexNS,
	protectSOA,
}

// allProtectPolicies backs the "all" keyword and is currently identical to
// defaultProtectPolicies (every known policy is on by default). They are kept
// as separate lists so that when a future policy is added that should NOT be
// part of the default safety set, it can be appended here without silently
// changing "default". Add any new built-in policy to this list, and to
// defaultProtectPolicies as well unless it is intentionally opt-in.
var allProtectPolicies = []string{
	protectCaddyACME,
	protectCaddyECH,
	protectApexNS,
	protectSOA,
}

var knownProtectPolicies = policySet(allProtectPolicies...)

// Start launches the initial sync in the background. Following the dynamicdns
// pattern, it does not block: if the initial sync fails (e.g. the network is
// not ready at boot, or a provider is briefly unreachable), it is retried with
// exponential backoff until it succeeds or the app is stopped. Per-zone
// failures are isolated and logged; they do not abort other zones.
func (a *App) Start() error {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.syncLoop()
	}()
	return nil
}

// Stop stops the app module. It cancels the app's own context, which unblocks
// the background sync loop promptly (rather than relying on Caddy cancelling
// the parent context, which happens only after Stop returns), then waits for
// the loop to finish to avoid zone sync conflicts if the app is quickly
// restarted. Stop panics if the app was not provisioned first.
func (a *App) Stop() error {
	a.cancel()
	a.wg.Wait()
	return nil
}

// syncLoop runs the initial reconcile, retrying with backoff until every zone
// has synced at least once (or the context is cancelled). Each retry pass only
// re-syncs the zones that are still failing, so the working set shrinks as
// zones recover.
func (a *App) syncLoop() {
	backoff := initialSyncBackoff
	zonesToSync := a.normalizedZones
	for {
		errs := a.syncZones(zonesToSync)

		// Carry only the zones that still failed into the next pass. errs is
		// positionally aligned to zonesToSync, so index into that, not a.Zones.
		// Build a fresh slice rather than reslicing zonesToSync, which on the
		// first pass aliases a.Zones and would corrupt its ordering.
		var next []*ZoneConfig
		for i, err := range errs {
			if err != nil {
				next = append(next, zonesToSync[i])
			}
		}
		zonesToSync = next

		if len(zonesToSync) == 0 {
			return
		}

		// syncAll already logged per-zone errors; here we just schedule a retry.
		a.logger.Warn("initial zone sync incomplete; will retry",
			zap.Int("remaining", len(zonesToSync)),
			zap.Duration("in", backoff), zap.Error(errors.Join(errs...)))

		select {
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxSyncBackoff {
				backoff = maxSyncBackoff
			}
		case <-a.ctx.Done():
			return
		}
	}
}

// syncZones reconciles the given zones concurrently. Each zone is independent: a
// failure in one is logged and does not prevent others from syncing. It returns
// a slice of per-zone errors, positionally aligned to zones (nil where the zone
// synced), so the caller can decide which zones to retry.
func (a *App) syncZones(zones []*ZoneConfig) []error {
	var wg sync.WaitGroup
	errs := make([]error, len(zones))
	for i, zc := range zones {
		wg.Add(1)
		go func(i int, zc *ZoneConfig) {
			defer wg.Done()
			err := a.syncZone(zc)
			if err != nil {
				a.logger.Error("zone sync failed",
					zap.String("zone", zc.ZoneName), zap.Error(err))
			}
			errs[i] = err
		}(i, zc)
	}
	wg.Wait()
	return errs
}

// rrsetKey identifies an RRset: a (name, type) pair. The name is the
// fully-qualified, lowercased form so that comparisons are robust to
// relative/absolute and case differences between the config and the provider.
type rrsetKey struct {
	name string
	typ  string
}

func (k rrsetKey) String() string { return k.name + " " + k.typ }

// keyOf computes the RRset key for a record within a zone.
func keyOf(rr libdns.RR, zone string) rrsetKey {
	return rrsetKey{
		name: strings.ToLower(libdns.AbsoluteName(rr.Name, zone)),
		typ:  strings.ToUpper(rr.Type),
	}
}

// syncZone reconciles a single zone toward its declared desired state with the
// following algorithm:
//
//  1. Parse the desired records and read the current zone contents.
//  2. Mark RRsets containing a protected record so they are never written or
//     deleted.
//  3. For each desired RRset, decide create / update / unchanged. SetRecords
//     replaces an entire (name, type) RRset, so a changed RRset contributes
//     all of its desired records to the "set" batch.
//  4. In mirror mode only, managed-eligible current RRsets that are not
//     declared are deleted.
//  5. In report mode, log what would change and make no mutations.
func (a *App) syncZone(zc *ZoneConfig) error {
	ctx := a.ctx
	zone := zc.ZoneName
	log := a.logger.With(zap.String("zone", zone), zap.String("sync_mode", zc.SyncMode))

	desired, err := zc.parsedRecords()
	if err != nil {
		return err
	}

	current, err := zc.provider.GetRecords(ctx, zone)
	if err != nil {
		return fmt.Errorf("getting current records: %w", err)
	}

	// Determine which RRsets are protected by built-in policies or RRset filters.
	protected := make(map[rrsetKey]bool)
	for _, rec := range current {
		rr := rec.RR()
		if ok, err := zc.isProtected(rr, zone); err != nil {
			return err
		} else if ok {
			protected[keyOf(rr, zone)] = true
		}
	}

	desiredByKey := groupByRRset(desired, zone)
	currentByKey := groupByRRset(current, zone)

	// Calculate the desired records to apply, accounting for protected RRsets.
	var toApply []libdns.Record
	var created, updated, matched int
	for key, drecs := range desiredByKey {
		if protected[key] {
			// A declared RRset whose *live* records are protected. A static
			// protection conflict would have been rejected at provision time, so
			// reaching here means the protection is data-dependent: most
			// commonly a live HTTPS record that Caddy has augmented with an ECH
			// "ech=" SvcParam (which the declared record doesn't carry). We
			// leave the RRset untouched rather than overwrite it and clobber
			// what Caddy is managing.
			log.Warn("declared RRset is protected in the live zone; leaving it untouched",
				zap.String("name", key.name),
				zap.String("type", key.typ),
				zap.String("hint", "a live record for this name/type is protected (e.g. an HTTPS record carrying a Caddy ECH ech= param); this module will not overwrite it"),
			)
			continue
		}
		crecs, exists := currentByKey[key]
		// In upsert mode the idempotency predicate is a subset check: if
		// every desired record is already present in the live RRset (with
		// the right data and TTL), the RRset is considered up-to-date even
		// if the live RRset contains additional undeclared members.
		isMatch := rrsetEqual(drecs, crecs)
		if !isMatch && zc.SyncMode == syncModeUpsert {
			isMatch = rrsetSubset(drecs, crecs)
		}
		switch {
		case !exists:
			toApply = append(toApply, drecs...)
			created += len(drecs)
			log.Debug("RRset will be created", zap.String("rrset", key.String()))
		case isMatch:
			matched += len(drecs)
		default:
			// SetRecords replaces the whole RRset, so we must send every
			// member we want to keep. In upsert mode that means merging
			// the desired records with any undeclared current members so
			// that SetRecords does not silently delete sibling records
			// within the same RRset. In mirror mode we only send the
			// desired records (undeclared siblings will be removed). In
			// both cases the current TTL is preserved for members whose
			// desired TTL is 0 ("provider decides").
			if zc.SyncMode == syncModeUpsert {
				toApply = append(toApply, mergeRRsets(drecs, crecs)...)
			} else {
				toApply = append(toApply, withPreservedTTLs(drecs, crecs)...)
			}
			updated += len(drecs)
			log.Debug("RRset will be updated", zap.String("rrset", key.String()))
		}
	}

	// Calculate the desired records to delete, accounting for protected RRsets.
	var toDelete []libdns.Record
	var deleted, skipped int
	for key, crecs := range currentByKey {
		if protected[key] {
			skipped += len(crecs)
			log.Debug("existing RRset is protected; leaving it untouched",
				zap.String("name", key.name), zap.String("type", key.typ), zap.Int("count", len(crecs)))
			continue
		}
		if _, inDesired := desiredByKey[key]; inDesired {
			// Declared RRsets are reconciled via SetRecords above.
			continue
		}
		toDelete = append(toDelete, crecs...)
		deleted += len(crecs)
		log.Debug("RRset will be deleted", zap.String("rrset", key.String()))
	}

	switch zc.SyncMode {
	case syncModeReport:
		a.logReport(log, toApply, toDelete)
		log.Info("zone sync report",
			zap.Int("would_create", created),
			zap.Int("would_update", updated),
			zap.Int("matched", matched),
			zap.Int("would_delete", deleted),
			zap.Int("would_skip", skipped))
	case syncModeUpsert:
		if len(toApply) > 0 {
			if err := zc.mutator.apply(ctx, zone, toApply, nil /* pass nothing in upsert mode */); err != nil {
				return err
			}
		}
		log.Info("zone synced",
			zap.Int("created", created),
			zap.Int("updated", updated),
			zap.Int("matched", matched),
			zap.Int("would_delete", deleted),
			zap.Int("would_skip", skipped))
	case syncModeMirror:
		if len(toApply) > 0 || len(toDelete) > 0 {
			if err := zc.mutator.apply(ctx, zone, toApply, toDelete); err != nil {
				return err
			}
		}
		log.Info("zone synced",
			zap.Int("created", created),
			zap.Int("updated", updated),
			zap.Int("matched", matched),
			zap.Int("deleted", deleted),
			zap.Int("skipped", skipped))
	default:
		return fmt.Errorf("unsupported sync mode: %q", zc.SyncMode)
	}
	return nil
}

// logReport emits one info line per pending change (used in report mode).
func (a *App) logReport(log *zap.Logger, toApply, toDelete []libdns.Record) {
	for _, r := range toApply {
		rr := r.RR()
		log.Info("report: set record",
			zap.String("name", rr.Name), zap.String("type", rr.Type),
			zap.Duration("ttl", rr.TTL), zap.String("data", rr.Data))
	}
	for _, r := range toDelete {
		rr := r.RR()
		log.Info("report: delete record",
			zap.String("name", rr.Name), zap.String("type", rr.Type),
			zap.String("data", rr.Data))
	}
}

// groupByRRset groups records by their RRset key (fully-qualified name + type).
func groupByRRset(recs []libdns.Record, zone string) map[rrsetKey][]libdns.Record {
	m := make(map[rrsetKey][]libdns.Record)
	for _, r := range recs {
		k := keyOf(r.RR(), zone)
		m[k] = append(m[k], r)
	}
	return m
}

// rrsetEqual reports whether the desired and current members of an RRset are
// equivalent, so the RRset can be skipped (idempotency).
//
// Comparison is by the set of RDATA values, each first normalized to libdns's
// canonical presentation form (see canonicalData) so that records differing
// only in formatting — e.g. IPv6 compression, CAA quoting, or internal
// whitespace — are recognized as equal rather than being rewritten on every
// sync. TTL is compared per value, but only when the desired TTL is non-zero:
// a desired TTL of 0 means "let the provider decide", so the provider's
// effective TTL must be ignored for the idempotency check.
func rrsetEqual(desired, current []libdns.Record) bool {
	dm := dataTTLMap(desired)
	cm := dataTTLMap(current)
	if len(dm) != len(cm) {
		return false
	}
	for data, dttl := range dm {
		cttl, ok := cm[data]
		if !ok {
			return false
		}
		if dttl != 0 && dttl != cttl {
			return false
		}
	}
	return true
}

// dataTTLMap maps each record's canonical RDATA to its TTL within an RRset.
func dataTTLMap(recs []libdns.Record) map[string]time.Duration {
	m := make(map[string]time.Duration, len(recs))
	for _, r := range recs {
		rr := r.RR()
		m[canonicalData(rr)] = rr.TTL
	}
	return m
}

// canonicalData returns a normalized presentation form of a record's RDATA so
// that desired records (parsed from config) and current records (returned by a
// provider) compare equal whenever they represent the same data, even if their
// raw RDATA differs only in formatting — e.g. IPv6 compression (AAAA), flag and
// quoting style (CAA), or internal whitespace (MX/SRV). Without this, a
// provider that echoes RDATA in a different-but-equivalent form would cause the
// RRset to be rewritten on every sync, defeating idempotency.
//
// It parses the RDATA into its typed libdns form and re-serializes it, which
// yields libdns's canonical presentation. If parsing fails, the trimmed raw
// RDATA is used as-is.
//
// HTTPS/SVCB records are deliberately NOT canonicalized: libdns serializes
// their SvcParams from a Go map, so the re-serialized order is
// non-deterministic and round-tripping could make equal records compare
// unequal. TXT records are opaque to libdns (round-trip is a no-op), so their
// data is effectively returned trimmed. Both fall back to the trimmed raw
// RDATA.
func canonicalData(rr libdns.RR) string {
	switch strings.ToUpper(rr.Type) {
	case "HTTPS", "SVCB":
		return strings.TrimSpace(rr.Data)
	}
	if rec, err := rr.Parse(); err == nil {
		return strings.TrimSpace(rec.RR().Data)
	}
	return strings.TrimSpace(rr.Data)
}

// withPreservedTTLs returns the desired records to write for a changed RRset,
// substituting the current TTL for any desired record that (a) has TTL 0
// ("provider decides") and (b) matches the RDATA of an existing record with a
// non-zero TTL. Because SetRecords replaces the entire RRset, this keeps a
// change to one member from resetting the provider-assigned TTLs of the
// members that aren't actually changing. Records with an explicit (non-zero)
// desired TTL, or whose data is new, are returned unchanged.
func withPreservedTTLs(desired, current []libdns.Record) []libdns.Record {
	curTTL := dataTTLMap(current)
	out := make([]libdns.Record, 0, len(desired))
	for _, r := range desired {
		rr := r.RR()
		if rr.TTL == 0 {
			if t, ok := curTTL[canonicalData(rr)]; ok && t != 0 {
				rr.TTL = t
				// Parse cannot fail here: these records were already
				// validated at provision time and only the TTL changed.
				rec, _ := rr.Parse()
				out = append(out, rec)
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// rrsetSubset reports whether every desired record is already present in the
// current RRset with matching data (and matching TTL when the desired TTL is
// non-zero). Unlike rrsetEqual it does not require the sizes to match —
// current may contain extra undeclared members. This is the correct
// idempotency predicate for upsert mode.
func rrsetSubset(desired, current []libdns.Record) bool {
	cm := dataTTLMap(current)
	for _, r := range desired {
		rr := r.RR()
		cttl, ok := cm[canonicalData(rr)]
		if !ok {
			return false
		}
		if rr.TTL != 0 && rr.TTL != cttl {
			return false
		}
	}
	return true
}

// mergeRRsets returns the records to write to a provider in upsert mode when
// a desired RRset diverges from the current one. It starts with
// withPreservedTTLs(desired, current) — giving desired records precedence
// with TTL carry-over for unchanged data — and then appends any current
// records whose RDATA is not covered by desired, so that SetRecords does not
// inadvertently delete sibling records within the same RRset.
func mergeRRsets(desired, current []libdns.Record) []libdns.Record {
	merged := withPreservedTTLs(desired, current)
	desiredData := make(map[string]bool, len(desired))
	for _, r := range desired {
		desiredData[canonicalData(r.RR())] = true
	}
	for _, r := range current {
		if !desiredData[canonicalData(r.RR())] {
			merged = append(merged, r)
		}
	}
	return merged
}

// normalizeProtectPolicies validates a user-specified built-in protection
// list and returns the effective policy set. An omitted list and ["default"]
// both mean the default safety set; ["none"] disables built-ins; ["all"]
// enables every known policy. Otherwise, the list is an exact set of policy
// names.
func normalizeProtectPolicies(policies []string) (map[string]bool, error) {
	if len(policies) == 0 {
		return policySet(defaultProtectPolicies...), nil
	}
	if len(policies) == 1 {
		switch strings.ToLower(strings.TrimSpace(policies[0])) {
		case "default":
			return policySet(defaultProtectPolicies...), nil
		case "none":
			return make(map[string]bool), nil
		case "all":
			return policySet(allProtectPolicies...), nil
		}
	}

	out := make(map[string]bool, len(policies))
	for _, policy := range policies {
		policy = strings.ToLower(strings.TrimSpace(policy))
		if policy == "" {
			return nil, fmt.Errorf("protect contains an empty policy name")
		}
		if policy == "default" || policy == "none" || policy == "all" {
			return nil, fmt.Errorf("protect keyword %q must be used by itself", policy)
		}
		if !knownProtectPolicies[policy] {
			return nil, fmt.Errorf("unknown protect policy %q", policy)
		}
		out[policy] = true
	}
	return out, nil
}

func policySet(policies ...string) map[string]bool {
	out := make(map[string]bool, len(policies))
	for _, policy := range policies {
		out[policy] = true
	}
	return out
}

// isProtected reports whether a record is shielded from modification/deletion
// by any built-in protection policy or explicit RRset matcher, regardless of
// sync_mode.
func (zc *ZoneConfig) isProtected(rr libdns.RR, zone string) (bool, error) {
	policies := zc.protectPolicies
	if policies == nil {
		return false, fmt.Errorf("isProtected: protectPolicies is nil")
	}
	if policies[protectCaddyACME] && isCaddyACME(rr, zone) {
		return true, nil
	}
	if policies[protectCaddyECH] && isCaddyECH(rr) {
		return true, nil
	}
	if policies[protectApexNS] && isApexNS(rr, zone) {
		return true, nil
	}
	if policies[protectSOA] && isSOA(rr) {
		return true, nil
	}
	for _, m := range zc.ProtectRRsets {
		if matchProtectRRset(m, rr, zone) {
			return true, nil
		}
	}
	return false, nil
}

// matchProtectRRset reports whether a structured RRset matcher ([type,
// name...]) matches a record. A type of "*" matches any type.
func matchProtectRRset(matcher []string, rr libdns.RR, zone string) bool {
	if len(matcher) < 2 {
		return false
	}
	if matcher[0] != "*" && !strings.EqualFold(matcher[0], rr.Type) {
		return false
	}
	name := strings.ToLower(libdns.AbsoluteName(rr.Name, zone))
	for _, n := range matcher[1:] {
		if strings.ToLower(libdns.AbsoluteName(n, zone)) == name {
			return true
		}
	}
	return false
}

// isCaddyACME heuristically reports whether a record is related to Caddy's
// ACME DNS-01 automation. It matches everything under
// _acme-challenge[.<name>] regardless of type so that both the challenge TXT
// Caddy writes and a user's _acme-challenge CNAME delegation are protected.
func isCaddyACME(rr libdns.RR, zone string) bool {
	rel := strings.ToLower(libdns.RelativeName(libdns.AbsoluteName(rr.Name, zone), zone))
	return rel == "_acme-challenge" || strings.HasPrefix(rel, "_acme-challenge.")
}

// isCaddyECH reports whether a record carries an ECH SvcParam, which Caddy may
// publish on HTTPS/SVCB records for Encrypted ClientHello.
func isCaddyECH(rr libdns.RR) bool {
	switch strings.ToUpper(rr.Type) {
	case "HTTPS", "SVCB":
		return hasSvcParam(rr.Data, "ech")
	}
	return false
}

func isApexNS(rr libdns.RR, zone string) bool {
	return strings.EqualFold(rr.Type, "NS") && libdns.RelativeName(libdns.AbsoluteName(rr.Name, zone), zone) == "@"
}

func isSOA(rr libdns.RR) bool {
	return strings.EqualFold(rr.Type, "SOA")
}

// hasSvcParam reports whether the presentation-format SVCB/HTTPS RDATA carries
// the named SvcParamKey. RDATA looks like "<priority> <target> key=val key=val",
// so we scan the space-separated tokens for one whose key matches.
func hasSvcParam(data, key string) bool {
	for _, tok := range strings.Fields(data) {
		if name, _, found := strings.Cut(tok, "="); found && strings.EqualFold(name, key) {
			return true
		}
	}
	return false
}
