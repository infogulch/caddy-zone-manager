package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// expectedCaseFiles is the authoritative list of case files (see
// cases/README.md for the group breakdown). The test fails if a file is
// missing or an unlisted .json file appears, so this list and the directory
// stay in lockstep and accidental additions/deletions are caught.
var expectedCaseFiles = []string{
	"001-report-no-mutation.json",
	"002-report-idempotent.json",
	"010-upsert-a.json",
	"011-upsert-aaaa.json",
	"012-upsert-txt.json",
	"013-upsert-cname.json",
	"014-upsert-mx.json",
	"015-upsert-caa.json",
	"016-upsert-srv.json",
	"017-upsert-ns-sub.json",
	"018-upsert-https.json",
	"020-update-a-value.json",
	"021-update-txt-content.json",
	"022-upsert-preserves-undeclared.json",
	"023a-upsert-sibling-plant.json",
	"023b-upsert-preserves-sibling.json",
	"030-ttl-explicit.json",
	"031-ttl-default.json",
	"032-ttl-zero-idempotency.json",
	"033-ttl-update.json",
	"040-mirror-deletes-undeclared.json",
	"041-mirror-creates.json",
	"042-mirror-updates.json",
	"043-mirror-empty.json",
	"044a-mirror-sibling-plant.json",
	"044b-mirror-sibling-removed.json",
	"050-protect-apex-ns.json",
	"051-protect-soa.json",
	"052a-protect-rrset-plant.json",
	"052b-protect-rrset-custom.json",
	"053-protect-none-report.json",
	"054a-protect-caddy-acme-plant.json",
	"054b-protect-caddy-acme.json",
	"060-idempotency-upsert.json",
	"061-idempotency-mirror.json",
	"062a-idempotency-aaaa-establish.json",
	"062b-idempotency-aaaa-normalize.json",
	"063a-idempotency-caa-establish.json",
	"063b-idempotency-caa-normalize.json",
}

// syncFieldsByMode mirrors the fields the module's sync.go emits in each
// mode's "zone synced" / "zone sync report" log line. A case may only assert
// fields its mode emits (PLAN "Field notes").
var syncFieldsByMode = map[string]map[string]bool{
	"report": {"would_create": true, "would_update": true, "matched": true, "would_delete": true, "would_skip": true},
	"upsert": {"created": true, "updated": true, "matched": true, "would_delete": true, "would_skip": true},
	"mirror": {"created": true, "updated": true, "matched": true, "deleted": true, "skipped": true},
}

const (
	testNonce = "deadbeef"
	testZone  = "example.com."
)

var tokenRe = regexp.MustCompile(`\{\{[^}]*\}\}`)

func TestCaseFilesMatchPlan(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("cases", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range paths {
		got = append(got, filepath.Base(p))
	}
	sort.Strings(got)

	want := append([]string(nil), expectedCaseFiles...)
	sort.Strings(want)

	wantSet := make(map[string]bool, len(want))
	for _, f := range want {
		wantSet[f] = true
	}
	gotSet := make(map[string]bool, len(got))
	for _, f := range got {
		gotSet[f] = true
	}
	for _, f := range want {
		if !gotSet[f] {
			t.Errorf("missing case file: %s", f)
		}
	}
	for _, f := range got {
		if !wantSet[f] {
			t.Errorf("unexpected case file (not in expectedCaseFiles): %s", f)
		}
	}
}

func TestLoadCases(t *testing.T) {
	cases, err := loadCases("cases", testNonce, testZone)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != len(expectedCaseFiles) {
		t.Errorf("loaded %d cases, want %d", len(cases), len(expectedCaseFiles))
	}
	for _, c := range cases {
		if c.Name == "" {
			t.Errorf("%s: empty name after defaulting", c.File)
		}
		if c.Tier != tierCritical && c.Tier != tierAdvisory {
			t.Errorf("%s: invalid tier %q", c.File, c.Tier)
		}
	}
}

// TestCaseFilesStrict re-decodes every case file with DisallowUnknownFields
// so typos in field names (which json.Unmarshal silently drops) fail loudly,
// then checks per-case semantic rules.
func TestCaseFilesStrict(t *testing.T) {
	for _, name := range expectedCaseFiles {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("cases", name))
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.ReplaceAll(raw, []byte("{{nonce}}"), []byte(testNonce))
			raw = bytes.ReplaceAll(raw, []byte("{{zone}}"), []byte(testZone))

			// No unrecognized tokens left behind (catches {{ nonce }}, {{Zone}}, …).
			if m := tokenRe.Find(raw); m != nil {
				t.Errorf("unrecognized template token %q", m)
			}

			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var c Case
			if err := dec.Decode(&c); err != nil {
				t.Fatalf("strict decode: %v", err)
			}

			mode := c.ApplyZone.SyncMode
			allowed, ok := syncFieldsByMode[mode]
			if !ok {
				t.Fatalf("invalid sync_mode %q", mode)
			}

			for k := range c.ExpectSync {
				base, _ := strings.CutSuffix(k, "_min")
				if !allowed[base] {
					t.Errorf("expect_sync field %q is not emitted in %s mode", k, mode)
				}
			}

			for i, r := range c.ApplyZone.Records {
				if r.Name == "" || r.Type == "" {
					t.Errorf("records[%d]: name and type are required", i)
				}
				if r.TTL < 0 {
					t.Errorf("records[%d]: negative ttl", i)
				}
			}
			for i, a := range c.ExpectRR {
				if a.Name == "" || a.Type == "" {
					t.Errorf("expect_rr[%d]: name and type are required", i)
				}
			}
			for i, a := range c.AbsentRR {
				if a.Name == "" || a.Type == "" {
					t.Errorf("absent_rr[%d]: name and type are required", i)
				}
				if a.TTL != 0 {
					t.Errorf("absent_rr[%d]: ttl is meaningless on an absence assertion", i)
				}
			}
		})
	}
}
