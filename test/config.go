package main

import (
	"encoding/json"
	"time"
)

// Sec is one second expressed in the nanosecond units used by the Caddy JSON
// schema's time.Duration fields (e.g. 300*Sec == 300000000000).
const Sec = int64(time.Second)

// Record is one DNS record in the dns_zone app's JSON schema (libdns.RR).
// Names are partially qualified relative to the zone; "@" is the apex.
type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl,omitempty"` // nanoseconds; 0 = provider decides
	Data string `json:"data,omitempty"`
}

// ApplyZone is the per-case subset of the dns_zone ZoneConfig schema.
// zone_name and dns_provider are injected by the harness from CLI flags.
type ApplyZone struct {
	SyncMode      string     `json:"sync_mode"`
	DefaultTTL    int64      `json:"default_ttl,omitempty"`
	Protect       []string   `json:"protect,omitempty"`
	ProtectRRsets [][]string `json:"protect_rrsets,omitempty"`
	Records       []Record   `json:"records"`
}

// zoneConfig mirrors the module's ZoneConfig JSON schema.
type zoneConfig struct {
	ZoneName      string          `json:"zone_name"`
	DNSProvider   json.RawMessage `json:"dns_provider"`
	SyncMode      string          `json:"sync_mode"`
	DefaultTTL    int64           `json:"default_ttl,omitempty"`
	Protect       []string        `json:"protect,omitempty"`
	ProtectRRsets [][]string      `json:"protect_rrsets,omitempty"`
	Records       []Record        `json:"records"`
}

type caddyConfig struct {
	Admin   adminConfig   `json:"admin"`
	Logging loggingConfig `json:"logging"`
	Apps    appsConfig    `json:"apps"`
}

type adminConfig struct {
	Listen string `json:"listen"`
}

type loggingConfig struct {
	Logs map[string]logConfig `json:"logs"`
}

type logConfig struct {
	Writer  map[string]any `json:"writer"`
	Encoder map[string]any `json:"encoder"`
	Level   string         `json:"level"`
}

type appsConfig struct {
	DNSZone dnsZoneApp `json:"dns_zone"`
}

type dnsZoneApp struct {
	Zones []zoneConfig `json:"zones"`
}

// buildCaddyConfig builds the full per-step Caddy JSON config document from a
// case's apply_zone plus the CLI-supplied zone name and provider JSON. It
// returns the marshaled config and a copy with dns_provider replaced by
// {"redacted": true}, which is the only form that may be written to the run
// log (the provider config typically contains an API token).
func buildCaddyConfig(zone string, provider json.RawMessage, az ApplyZone, adminAddr, caddyLogPath string) (cfg, redacted []byte, err error) {
	records := az.Records
	if records == nil {
		records = []Record{}
	}
	doc := caddyConfig{
		Admin: adminConfig{Listen: adminAddr},
		Logging: loggingConfig{Logs: map[string]logConfig{
			"default": {
				Writer:  map[string]any{"output": "file", "filename": caddyLogPath},
				Encoder: map[string]any{"format": "json"},
				Level:   "DEBUG",
			},
		}},
		Apps: appsConfig{DNSZone: dnsZoneApp{Zones: []zoneConfig{{
			ZoneName:      zone,
			DNSProvider:   provider,
			SyncMode:      az.SyncMode,
			DefaultTTL:    az.DefaultTTL,
			Protect:       az.Protect,
			ProtectRRsets: az.ProtectRRsets,
			Records:       records,
		}}}},
	}
	cfg, err = json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	doc.Apps.DNSZone.Zones[0].DNSProvider = json.RawMessage(`{"redacted":true}`)
	redacted, err = json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	return cfg, redacted, nil
}
