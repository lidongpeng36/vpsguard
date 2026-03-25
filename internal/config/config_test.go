package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Mode != ModeBlocklist {
		t.Errorf("default mode = %q, want %q", cfg.Mode, ModeBlocklist)
	}
	if cfg.NFTables.TableName != "vpsguard" {
		t.Errorf("default table name = %q, want %q", cfg.NFTables.TableName, "vpsguard")
	}
	if cfg.NFTables.Priority != -1 {
		t.Errorf("default priority = %d, want -1", cfg.NFTables.Priority)
	}
	if cfg.Log.Level != LogInfo {
		t.Errorf("default log level = %q, want %q", cfg.Log.Level, LogInfo)
	}
	if cfg.Daemon.CleanupOnStop != true {
		t.Error("default cleanup_on_stop should be true")
	}
	if cfg.GeoIP.UpdateInterval != "48h" {
		t.Errorf("default update_interval = %q, want %q", cfg.GeoIP.UpdateInterval, "48h")
	}
}

func TestParseValidBlocklist(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
  - RU
whitelist:
  - 1.2.3.4
  - 10.0.0.0/8
geoip:
  license_key: "test-key"
  data_dir: /tmp/geoip
nftables:
  table_name: vpsguard
  priority: -1
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != ModeBlocklist {
		t.Errorf("mode = %q, want %q", cfg.Mode, ModeBlocklist)
	}
	if len(cfg.Countries) != 2 {
		t.Errorf("countries count = %d, want 2", len(cfg.Countries))
	}
	if cfg.Countries[0] != "CN" || cfg.Countries[1] != "RU" {
		t.Errorf("countries = %v, want [CN RU]", cfg.Countries)
	}
	if len(cfg.Whitelist) != 2 {
		t.Errorf("whitelist count = %d, want 2", len(cfg.Whitelist))
	}
}

func TestParseValidAllowlist(t *testing.T) {
	yaml := `
mode: allowlist
countries:
  - US
  - JP
  - SG
whitelist:
  - 192.168.1.0/24
geoip:
  license_key: "test-key"
  data_dir: /tmp/geoip
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != ModeAllowlist {
		t.Errorf("mode = %q, want %q", cfg.Mode, ModeAllowlist)
	}
	if len(cfg.Countries) != 3 {
		t.Errorf("countries count = %d, want 3", len(cfg.Countries))
	}
}

func TestParseInvalidMode(t *testing.T) {
	yaml := `
mode: invalid
countries:
  - CN
geoip:
  license_key: "key"
  data_dir: /tmp
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if got := err.Error(); !contains(got, "invalid mode") {
		t.Errorf("error = %q, want to contain 'invalid mode'", got)
	}
}

func TestParseInvalidCountryCode(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantErr string
	}{
		{"too long", "USA", "must be 2-letter"},
		{"too short", "C", "must be 2-letter"},
		{"lowercase", "cn", "must be uppercase"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
mode: blocklist
countries:
  - ` + tt.code + `
geoip:
  license_key: "key"
  data_dir: /tmp
`
			_, err := Parse([]byte(yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseEmptyCountries(t *testing.T) {
	yaml := `
mode: blocklist
countries: []
geoip:
  license_key: "key"
  data_dir: /tmp
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for empty countries")
	}
	if !contains(err.Error(), "countries list is empty") {
		t.Errorf("error = %q, want to contain 'countries list is empty'", err.Error())
	}
}

func TestParseInvalidWhitelist(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
whitelist:
  - not-an-ip
geoip:
  license_key: "key"
  data_dir: /tmp
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid whitelist entry")
	}
	if !contains(err.Error(), "invalid whitelist entry") {
		t.Errorf("error = %q, want to contain 'invalid whitelist entry'", err.Error())
	}
}

func TestParseMissingLicenseKey(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
geoip:
  data_dir: /tmp
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing license key")
	}
	if !contains(err.Error(), "license_key is required") {
		t.Errorf("error = %q, want to contain 'license_key is required'", err.Error())
	}
}

func TestParseInvalidUpdateInterval(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
geoip:
  license_key: "key"
  update_interval: "not-a-duration"
  data_dir: /tmp
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid update interval")
	}
	if !contains(err.Error(), "invalid geoip.update_interval") {
		t.Errorf("error = %q, want to contain 'invalid geoip.update_interval'", err.Error())
	}
}

func TestParseInvalidLogLevel(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
geoip:
  license_key: "key"
  data_dir: /tmp
log:
  level: verbose
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
	if !contains(err.Error(), "invalid log.level") {
		t.Errorf("error = %q, want to contain 'invalid log.level'", err.Error())
	}
}

func TestParseDefaultsApplied(t *testing.T) {
	// Minimal config - defaults should fill in the rest
	yaml := `
mode: blocklist
countries:
  - CN
geoip:
  license_key: "key"
  data_dir: /tmp
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Check defaults were applied
	if cfg.NFTables.TableName != "vpsguard" {
		t.Errorf("table_name = %q, want default %q", cfg.NFTables.TableName, "vpsguard")
	}
	if cfg.NFTables.Priority != -1 {
		t.Errorf("priority = %d, want default -1", cfg.NFTables.Priority)
	}
	if cfg.Log.Level != LogInfo {
		t.Errorf("log level = %q, want default %q", cfg.Log.Level, LogInfo)
	}
	if cfg.GeoIP.UpdateInterval != "48h" {
		t.Errorf("update_interval = %q, want default %q", cfg.GeoIP.UpdateInterval, "48h")
	}
	if cfg.GeoIP.Edition != "GeoLite2-Country-CSV" {
		t.Errorf("edition = %q, want default", cfg.GeoIP.Edition)
	}
}

func TestUpdateIntervalDuration(t *testing.T) {
	cfg := Defaults()
	cfg.GeoIP.UpdateInterval = "24h"
	if got := cfg.UpdateIntervalDuration(); got != 24*time.Hour {
		t.Errorf("duration = %v, want 24h", got)
	}

	cfg.GeoIP.UpdateInterval = "72h"
	if got := cfg.UpdateIntervalDuration(); got != 72*time.Hour {
		t.Errorf("duration = %v, want 72h", got)
	}
}

func TestParsedWhitelist(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
whitelist:
  - 1.2.3.4
  - 10.0.0.0/8
  - 2001:db8::1
  - 2001:db8::/32
geoip:
  license_key: "key"
  data_dir: /tmp
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	prefixes, err := cfg.ParsedWhitelist()
	if err != nil {
		t.Fatalf("ParsedWhitelist error: %v", err)
	}
	if len(prefixes) != 4 {
		t.Fatalf("got %d prefixes, want 4", len(prefixes))
	}

	// Single IPv4 → /32
	want0 := netip.MustParsePrefix("1.2.3.4/32")
	if prefixes[0] != want0 {
		t.Errorf("prefix[0] = %v, want %v", prefixes[0], want0)
	}

	// CIDR
	want1 := netip.MustParsePrefix("10.0.0.0/8")
	if prefixes[1] != want1 {
		t.Errorf("prefix[1] = %v, want %v", prefixes[1], want1)
	}

	// Single IPv6 → /128
	want2 := netip.MustParsePrefix("2001:db8::1/128")
	if prefixes[2] != want2 {
		t.Errorf("prefix[2] = %v, want %v", prefixes[2], want2)
	}

	// IPv6 CIDR
	want3 := netip.MustParsePrefix("2001:db8::/32")
	if prefixes[3] != want3 {
		t.Errorf("prefix[3] = %v, want %v", prefixes[3], want3)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
mode: allowlist
countries:
  - US
  - JP
whitelist:
  - 192.168.1.1
geoip:
  license_key: "file-test-key"
  data_dir: /tmp/geoip
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Mode != ModeAllowlist {
		t.Errorf("mode = %q, want %q", cfg.Mode, ModeAllowlist)
	}
	if cfg.GeoIP.LicenseKey != "file-test-key" {
		t.Errorf("license_key = %q, want %q", cfg.GeoIP.LicenseKey, "file-test-key")
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("{{{{invalid yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestWhitelistIPv6Only(t *testing.T) {
	yaml := `
mode: blocklist
countries:
  - CN
whitelist:
  - "::1"
  - "fe80::/10"
geoip:
  license_key: "key"
  data_dir: /tmp
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	prefixes, err := cfg.ParsedWhitelist()
	if err != nil {
		t.Fatalf("ParsedWhitelist error: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefixes))
	}
	// ::1 → /128
	if prefixes[0].Bits() != 128 {
		t.Errorf("prefix[0] bits = %d, want 128", prefixes[0].Bits())
	}
	// fe80::/10
	if prefixes[1].Bits() != 10 {
		t.Errorf("prefix[1] bits = %d, want 10", prefixes[1].Bits())
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
