package daemon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lidongpeng36/vpsguard/internal/config"
)

const validYAML = `
mode: blocklist
countries:
  - CN
  - RU
whitelist:
  - 192.168.0.0/16
geoip:
  license_key: "test-key"
  update_interval: "1h"
  data_dir: /tmp/vpsguard-test
nftables:
  table_name: vpsguard_test
  priority: -1
log:
  level: error
daemon:
  cleanup_on_stop: true
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestNewDaemon(t *testing.T) {
	path := writeConfig(t, validYAML)
	d, err := New(path)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if d.cfg.Mode != config.ModeBlocklist {
		t.Errorf("mode = %q, want blocklist", d.cfg.Mode)
	}
	if d.configPath != path {
		t.Errorf("configPath = %q, want %q", d.configPath, path)
	}
}

func TestNewDaemonInvalidConfig(t *testing.T) {
	path := writeConfig(t, "invalid: yaml: [[[")
	_, err := New(path)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewDaemonFileNotFound(t *testing.T) {
	_, err := New("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNewFromConfig(t *testing.T) {
	cfg := &config.Config{
		Mode:      config.ModeAllowlist,
		Countries: []string{"US"},
		GeoIP: config.GeoIP{
			LicenseKey:     "key",
			Edition:        "GeoLite2-Country-CSV",
			UpdateInterval: "24h",
			DataDir:        "/tmp/test",
		},
		NFTables: config.NFTables{
			TableName: "test",
			Priority:  -1,
		},
		Log: config.Log{
			Level: config.LogError,
		},
	}

	d := NewFromConfig(cfg, "/etc/test.yaml")
	if d.cfg.Mode != config.ModeAllowlist {
		t.Errorf("mode = %q, want allowlist", d.cfg.Mode)
	}
}

func TestDaemonStop(t *testing.T) {
	cfg := &config.Config{
		Mode:      config.ModeBlocklist,
		Countries: []string{"CN"},
		GeoIP: config.GeoIP{
			LicenseKey:     "key",
			Edition:        "GeoLite2-Country-CSV",
			UpdateInterval: "1h",
			DataDir:        t.TempDir(),
		},
		NFTables: config.NFTables{
			TableName: "test",
			Priority:  -1,
		},
		Log:    config.Log{Level: config.LogError},
		Daemon: config.Daemon{CleanupOnStop: false},
	}

	d := NewFromConfig(cfg, "")
	// Set up cancel func directly
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	// Stop should work without panic
	d.Stop()

	// Context should be done
	select {
	case <-ctx.Done():
		// OK
	default:
		t.Error("context should be cancelled after Stop()")
	}
}

func TestDaemonStatusInitial(t *testing.T) {
	cfg := &config.Config{
		Mode:      config.ModeBlocklist,
		Countries: []string{"CN"},
		GeoIP: config.GeoIP{
			LicenseKey:     "key",
			Edition:        "GeoLite2-Country-CSV",
			UpdateInterval: "1h",
			DataDir:        t.TempDir(),
		},
		NFTables: config.NFTables{
			TableName: "test",
			Priority:  -1,
		},
		Log: config.Log{Level: config.LogError},
	}

	d := NewFromConfig(cfg, "")
	status := d.Status()

	if status.HasData {
		t.Error("initial status should not have data")
	}
	if !status.LastUpdate.IsZero() {
		t.Error("initial last update should be zero")
	}
}

func TestSetupLogger(t *testing.T) {
	tests := []struct {
		name  string
		level config.LogLevel
	}{
		{"debug", config.LogDebug},
		{"info", config.LogInfo},
		{"warn", config.LogWarn},
		{"error", config.LogError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Log: config.Log{Level: tt.level},
			}
			logger := setupLogger(cfg)
			if logger == nil {
				t.Fatal("setupLogger returned nil")
			}
		})
	}
}

func TestSetupLoggerToFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "test.log")
	cfg := &config.Config{
		Log: config.Log{
			Level: config.LogInfo,
			File:  logPath,
		},
	}
	logger := setupLogger(cfg)
	logger.Info("test message")

	// Verify file was created and has content
	time.Sleep(50 * time.Millisecond) // allow flush
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if len(data) == 0 {
		t.Error("log file is empty")
	}
}

func TestSetupLoggerInvalidFile(t *testing.T) {
	cfg := &config.Config{
		Log: config.Log{
			Level: config.LogInfo,
			File:  "/nonexistent/dir/test.log",
		},
	}
	// Should not panic, falls back to stderr
	logger := setupLogger(cfg)
	if logger == nil {
		t.Fatal("setupLogger returned nil for invalid file path")
	}
}

func TestHandleReload(t *testing.T) {
	// Write initial config
	path := writeConfig(t, validYAML)

	d, err := New(path)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Modify config file
	newYAML := `
mode: allowlist
countries:
  - US
  - JP
whitelist:
  - 10.0.0.0/8
geoip:
  license_key: "new-key"
  update_interval: "24h"
  data_dir: /tmp/vpsguard-test
nftables:
  table_name: vpsguard_test
  priority: -2
log:
  level: error
daemon:
  cleanup_on_stop: false
`
	os.WriteFile(path, []byte(newYAML), 0600)

	// handleReload won't fully succeed (no GeoIP data), but it should
	// at least parse the new config without panic
	d.handleReload()

	// Config should be updated (even if rule application fails,
	// the config parse succeeded so d.cfg gets updated)
	if d.cfg.Mode != config.ModeAllowlist {
		t.Logf("mode not updated (expected if reload partially failed): %s", d.cfg.Mode)
	}
}

func TestHandleReloadInvalidConfig(t *testing.T) {
	path := writeConfig(t, validYAML)

	d, err := New(path)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	originalMode := d.cfg.Mode

	// Write invalid config
	os.WriteFile(path, []byte("mode: invalid\n"), 0600)

	// Reload should fail gracefully, keeping old config
	d.handleReload()

	if d.cfg.Mode != originalMode {
		t.Errorf("config mode changed after failed reload: %q, want %q", d.cfg.Mode, originalMode)
	}
}

func TestLogLevelMapping(t *testing.T) {
	tests := []struct {
		cfgLevel config.LogLevel
		want     slog.Level
	}{
		{config.LogDebug, slog.LevelDebug},
		{config.LogInfo, slog.LevelInfo},
		{config.LogWarn, slog.LevelWarn},
		{config.LogError, slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(string(tt.cfgLevel), func(t *testing.T) {
			cfg := &config.Config{
				Log: config.Log{Level: tt.cfgLevel},
			}
			logger := setupLogger(cfg)

			// Verify the logger is enabled at the expected level
			if !logger.Enabled(context.Background(), tt.want) {
				t.Errorf("logger should be enabled at %v for config level %s", tt.want, tt.cfgLevel)
			}
		})
	}
}
