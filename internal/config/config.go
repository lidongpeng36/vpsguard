// Package config handles loading and validating VPSGuard configuration.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode represents the firewall operating mode.
type Mode string

const (
	ModeBlocklist Mode = "blocklist"
	ModeAllowlist Mode = "allowlist"
)

// LogLevel represents log verbosity.
type LogLevel string

const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// Config is the top-level configuration structure.
type Config struct {
	Mode      Mode      `yaml:"mode"`
	Countries []string  `yaml:"countries"`
	Whitelist []string  `yaml:"whitelist"`
	GeoIP     GeoIP     `yaml:"geoip"`
	NFTables  NFTables  `yaml:"nftables"`
	Log       Log       `yaml:"log"`
	Daemon    Daemon    `yaml:"daemon"`
}

// GeoIP configures the MaxMind GeoIP data source.
type GeoIP struct {
	LicenseKey     string `yaml:"license_key"`
	Edition        string `yaml:"edition"`
	UpdateInterval string `yaml:"update_interval"`
	DataDir        string `yaml:"data_dir"`
}

// NFTables configures the nftables integration.
type NFTables struct {
	TableName string `yaml:"table_name"`
	Priority  int    `yaml:"priority"`
}

// Log configures logging behavior.
type Log struct {
	Level      LogLevel `yaml:"level"`
	File       string   `yaml:"file"`
	MaxSizeMB  int      `yaml:"max_size_mb"`
	MaxBackups int      `yaml:"max_backups"`
}

// Daemon configures daemon behavior.
type Daemon struct {
	CleanupOnStop   bool `yaml:"cleanup_on_stop"`
	BlockUntilReady bool `yaml:"block_until_ready"`
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() *Config {
	return &Config{
		Mode:      ModeBlocklist,
		Countries: []string{},
		Whitelist: []string{},
		GeoIP: GeoIP{
			Edition:        "GeoLite2-Country-CSV",
			UpdateInterval: "48h",
			DataDir:        "/var/lib/vpsguard/geoip",
		},
		NFTables: NFTables{
			TableName: "vpsguard",
			Priority:  -1,
		},
		Log: Log{
			Level:      LogInfo,
			MaxSizeMB:  100,
			MaxBackups: 3,
		},
		Daemon: Daemon{
			CleanupOnStop:   true,
			BlockUntilReady: false,
		},
	}
}

// Load reads and parses a YAML configuration file, applying defaults
// for any unset fields, then validates the result.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML bytes into a validated Config.
func Parse(data []byte) (*Config, error) {
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return cfg, nil
}

// Validate checks the configuration for logical errors.
func (c *Config) Validate() error {
	// Mode
	switch c.Mode {
	case ModeBlocklist, ModeAllowlist:
	default:
		return fmt.Errorf("invalid mode %q: must be %q or %q", c.Mode, ModeBlocklist, ModeAllowlist)
	}

	// Countries: must be 2-letter ISO codes
	for _, code := range c.Countries {
		if len(code) != 2 {
			return fmt.Errorf("invalid country code %q: must be 2-letter ISO 3166-1 alpha-2", code)
		}
		upper := strings.ToUpper(code)
		if upper != code {
			return fmt.Errorf("country code %q must be uppercase (use %q)", code, upper)
		}
	}

	// At least one country should be specified
	if len(c.Countries) == 0 {
		return fmt.Errorf("countries list is empty: specify at least one country code")
	}

	// Whitelist: must be valid IPs or CIDRs
	for _, entry := range c.Whitelist {
		if _, err := netip.ParsePrefix(entry); err != nil {
			// Try as single IP
			if _, err2 := netip.ParseAddr(entry); err2 != nil {
				return fmt.Errorf("invalid whitelist entry %q: not a valid IP or CIDR", entry)
			}
		}
	}

	// GeoIP
	if c.GeoIP.LicenseKey == "" {
		return fmt.Errorf("geoip.license_key is required")
	}
	if c.GeoIP.DataDir == "" {
		return fmt.Errorf("geoip.data_dir is required")
	}
	if _, err := time.ParseDuration(c.GeoIP.UpdateInterval); err != nil {
		return fmt.Errorf("invalid geoip.update_interval %q: %w", c.GeoIP.UpdateInterval, err)
	}

	// NFTables
	if c.NFTables.TableName == "" {
		return fmt.Errorf("nftables.table_name is required")
	}

	// Log level
	switch c.Log.Level {
	case LogDebug, LogInfo, LogWarn, LogError:
	case "":
		c.Log.Level = LogInfo
	default:
		return fmt.Errorf("invalid log.level %q", c.Log.Level)
	}

	return nil
}

// UpdateIntervalDuration returns the parsed update interval duration.
func (c *Config) UpdateIntervalDuration() time.Duration {
	d, _ := time.ParseDuration(c.GeoIP.UpdateInterval)
	return d
}

// ParsedWhitelist returns the whitelist entries as parsed netip.Prefix values.
// Single IPs are converted to /32 (IPv4) or /128 (IPv6) prefixes.
func (c *Config) ParsedWhitelist() ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, entry := range c.Whitelist {
		if p, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist entry %q", entry)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
	}
	return prefixes, nil
}
