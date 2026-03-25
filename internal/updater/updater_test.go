package updater

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lidongpeng36/vpsguard/internal/config"
	"github.com/lidongpeng36/vpsguard/internal/firewall"
	"github.com/lidongpeng36/vpsguard/internal/geoip"
)

// Test data constants (matching geoip test data)
const locationsCSV = `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
1814991,en,AS,Asia,CN,China,0
2017370,en,EU,Europe,RU,Russia,0
6252001,en,NA,"North America",US,"United States",0
`

const blocksV4CSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
1.0.1.0/24,1814991,1814991,,0,0,0
1.0.2.0/23,1814991,1814991,,0,0,0
37.0.0.0/16,2017370,2017370,,0,0,0
8.8.8.0/24,6252001,6252001,,0,0,0
`

const blocksV6CSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
2001:200::/32,1814991,1814991,,0,0,0
2a00::/16,2017370,2017370,,0,0,0
`

func setupTestData(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "geoip", "current")
	os.MkdirAll(dir, 0755)
	writeFile(t, dir, "GeoLite2-Country-Locations-en.csv", locationsCSV)
	writeFile(t, dir, "GeoLite2-Country-Blocks-IPv4.csv", blocksV4CSV)
	writeFile(t, dir, "GeoLite2-Country-Blocks-IPv6.csv", blocksV6CSV)
	return filepath.Dir(dir) // return the parent (data_dir)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func testConfig(dataDir string) *config.Config {
	return &config.Config{
		Mode:      config.ModeBlocklist,
		Countries: []string{"CN", "RU"},
		Whitelist: []string{"192.168.0.0/16", "10.0.0.1"},
		GeoIP: config.GeoIP{
			LicenseKey:     "test-key",
			Edition:        "GeoLite2-Country-CSV",
			UpdateInterval: "1h",
			DataDir:        dataDir,
		},
		NFTables: config.NFTables{
			TableName: "vpsguard_test",
			Priority:  -1,
		},
		Log: config.Log{
			Level: config.LogInfo,
		},
		Daemon: config.Daemon{
			CleanupOnStop: true,
		},
	}
}

func TestBuildParams(t *testing.T) {
	dataDir := setupTestData(t)
	cfg := testConfig(dataDir)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	u := New(cfg, logger)

	// Load CIDRs
	cidrs, err := geoip.LoadFromDir(filepath.Join(dataDir, "current"), cfg.Countries)
	if err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}

	params, err := u.BuildParamsFromData(cidrs)
	if err != nil {
		t.Fatalf("BuildParamsFromData: %v", err)
	}

	// Check mode
	if params.Mode != "blocklist" {
		t.Errorf("mode = %q, want blocklist", params.Mode)
	}

	// Check whitelist separation
	if len(params.WhitelistV4) != 2 {
		t.Errorf("WhitelistV4 count = %d, want 2", len(params.WhitelistV4))
	}

	// Check geo CIDRs aggregated
	if len(params.GeoV4) == 0 {
		t.Error("GeoV4 should not be empty")
	}
	if len(params.GeoV6) == 0 {
		t.Error("GeoV6 should not be empty")
	}

	// Verify specific CIDRs are present
	hasPrefix := func(prefixes []netip.Prefix, want string) bool {
		target := netip.MustParsePrefix(want)
		for _, p := range prefixes {
			if p == target {
				return true
			}
		}
		return false
	}

	if !hasPrefix(params.GeoV4, "1.0.1.0/24") {
		t.Error("missing CN prefix 1.0.1.0/24 in GeoV4")
	}
	if !hasPrefix(params.GeoV4, "37.0.0.0/16") {
		t.Error("missing RU prefix 37.0.0.0/16 in GeoV4")
	}
	if !hasPrefix(params.GeoV6, "2001:200::/32") {
		t.Error("missing CN prefix 2001:200::/32 in GeoV6")
	}
}

func TestBuildParamsAllowlist(t *testing.T) {
	dataDir := setupTestData(t)
	cfg := testConfig(dataDir)
	cfg.Mode = config.ModeAllowlist
	cfg.Countries = []string{"US"}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(cfg, logger)

	cidrs, err := geoip.LoadFromDir(filepath.Join(dataDir, "current"), cfg.Countries)
	if err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}

	params, err := u.BuildParamsFromData(cidrs)
	if err != nil {
		t.Fatalf("BuildParamsFromData: %v", err)
	}

	if params.Mode != "allowlist" {
		t.Errorf("mode = %q, want allowlist", params.Mode)
	}

	// In allowlist mode, GeoV4 should contain US CIDRs only
	if len(params.GeoV4) != 1 {
		t.Errorf("GeoV4 count = %d, want 1 (US only)", len(params.GeoV4))
	}
}

func TestBuildParamsWhitelistSeparation(t *testing.T) {
	dataDir := setupTestData(t)
	cfg := testConfig(dataDir)
	cfg.Whitelist = []string{"10.0.0.0/8", "::1", "2001:db8::/32"}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(cfg, logger)

	cidrs := geoip.NewCountryCIDRs()
	params, err := u.BuildParamsFromData(cidrs)
	if err != nil {
		t.Fatalf("BuildParamsFromData: %v", err)
	}

	// 10.0.0.0/8 → v4
	if len(params.WhitelistV4) != 1 {
		t.Errorf("WhitelistV4 count = %d, want 1", len(params.WhitelistV4))
	}
	// ::1 and 2001:db8::/32 → v6
	if len(params.WhitelistV6) != 2 {
		t.Errorf("WhitelistV6 count = %d, want 2", len(params.WhitelistV6))
	}
}

func TestGetStatusInitial(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(dataDir)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	u := New(cfg, logger)
	status := u.GetStatus()

	if status.HasData {
		t.Error("initial status should not have data")
	}
	if !status.LastUpdate.IsZero() {
		t.Error("initial last update should be zero")
	}
	if status.LastError != nil {
		t.Error("initial last error should be nil")
	}
}

func TestRunScheduleCancellation(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(dataDir)
	cfg.GeoIP.UpdateInterval = "100ms"

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		u.RunSchedule(ctx)
		close(done)
	}()

	// Let it tick once or twice
	time.Sleep(250 * time.Millisecond)
	cancel()

	// Should complete promptly
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("RunSchedule did not stop after context cancellation")
	}
}

func TestGenerateRulesetIntegration(t *testing.T) {
	// End-to-end: config → load GeoIP → build params → generate ruleset
	dataDir := setupTestData(t)
	cfg := testConfig(dataDir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(cfg, logger)

	cidrs, err := geoip.LoadFromDir(filepath.Join(dataDir, "current"), cfg.Countries)
	if err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}

	params, err := u.BuildParamsFromData(cidrs)
	if err != nil {
		t.Fatalf("BuildParamsFromData: %v", err)
	}

	fw := firewall.NewManager(cfg.NFTables.TableName, cfg.NFTables.Priority)
	ruleset := fw.GenerateRuleset(params)

	// Verify the complete ruleset contains expected elements
	checks := []string{
		"table inet vpsguard_test",
		"192.168.0.0/16",       // whitelist CIDR
		"10.0.0.1/32",          // whitelist single IP (converted to /32)
		"1.0.1.0/24",           // CN IPv4
		"37.0.0.0/16",          // RU IPv4
		"2001:200::/32",        // CN IPv6
		"blocked_v4",           // blocklist mode
		"ct state established", // requirement 3
	}
	for _, check := range checks {
		if !contains(ruleset, check) {
			t.Errorf("ruleset missing %q", check)
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
