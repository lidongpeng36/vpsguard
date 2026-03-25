// Package firewall generates and applies nftables rulesets for VPSGuard.
package firewall

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Manager handles nftables rule generation and application.
type Manager struct {
	TableName string
	Priority  int

	// NftBinary is the path to the nft binary. Defaults to "nft".
	NftBinary string
}

// NewManager creates a Manager with sensible defaults.
func NewManager(tableName string, priority int) *Manager {
	return &Manager{
		TableName: tableName,
		Priority:  priority,
		NftBinary: "nft",
	}
}

// RulesetParams holds all parameters needed to generate a complete nftables ruleset.
type RulesetParams struct {
	Mode        string           // "blocklist" or "allowlist"
	WhitelistV4 []netip.Prefix   // IPv4 whitelist CIDRs
	WhitelistV6 []netip.Prefix   // IPv6 whitelist CIDRs
	GeoV4       []netip.Prefix   // IPv4 country CIDRs (meaning depends on mode)
	GeoV6       []netip.Prefix   // IPv6 country CIDRs
}

// GenerateRuleset produces a complete nftables ruleset string.
func (m *Manager) GenerateRuleset(params *RulesetParams) string {
	var buf bytes.Buffer

	// Header
	fmt.Fprintf(&buf, "# VPSGuard nftables ruleset - auto-generated\n")
	fmt.Fprintf(&buf, "# Mode: %s\n\n", params.Mode)

	// Delete existing table first (for atomic replace)
	fmt.Fprintf(&buf, "delete table inet %s\n\n", m.TableName)

	// Begin table
	fmt.Fprintf(&buf, "table inet %s {\n", m.TableName)

	// Whitelist sets
	m.writeSet(&buf, "whitelist_v4", "ipv4_addr", params.WhitelistV4)
	m.writeSet(&buf, "whitelist_v6", "ipv6_addr", params.WhitelistV6)

	// Geo sets
	if params.Mode == "blocklist" {
		m.writeSet(&buf, "blocked_v4", "ipv4_addr", params.GeoV4)
		m.writeSet(&buf, "blocked_v6", "ipv6_addr", params.GeoV6)
	} else {
		m.writeSet(&buf, "allowed_v4", "ipv4_addr", params.GeoV4)
		m.writeSet(&buf, "allowed_v6", "ipv6_addr", params.GeoV6)
	}

	// Chain
	m.writeChain(&buf, params.Mode)

	// End table
	fmt.Fprintf(&buf, "}\n")

	return buf.String()
}

// writeSet writes an nftables set definition with interval/auto-merge flags.
func (m *Manager) writeSet(buf *bytes.Buffer, name, addrType string, prefixes []netip.Prefix) {
	fmt.Fprintf(buf, "    set %s {\n", name)
	fmt.Fprintf(buf, "        type %s\n", addrType)
	fmt.Fprintf(buf, "        flags interval\n")
	fmt.Fprintf(buf, "        auto-merge\n")
	if len(prefixes) > 0 {
		fmt.Fprintf(buf, "        elements = { %s }\n", formatPrefixes(prefixes))
	}
	fmt.Fprintf(buf, "    }\n\n")
}

// writeChain writes the input chain with appropriate rules based on mode.
func (m *Manager) writeChain(buf *bytes.Buffer, mode string) {
	fmt.Fprintf(buf, "    chain input {\n")
	fmt.Fprintf(buf, "        type filter hook input priority %d; policy accept;\n\n", m.Priority)

	// Rule 1: Allow established/related (critical for requirement 3)
	fmt.Fprintf(buf, "        # Allow established/related connections (ensures outbound traffic works)\n")
	fmt.Fprintf(buf, "        ct state established,related accept\n\n")

	// Rule 2: Allow loopback
	fmt.Fprintf(buf, "        # Allow loopback\n")
	fmt.Fprintf(buf, "        iif lo accept\n\n")

	// Rule 3: Whitelist
	fmt.Fprintf(buf, "        # Whitelist always passes\n")
	fmt.Fprintf(buf, "        ip saddr @whitelist_v4 accept\n")
	fmt.Fprintf(buf, "        ip6 saddr @whitelist_v6 accept\n\n")

	if mode == "blocklist" {
		// Rule 4: Block listed countries
		fmt.Fprintf(buf, "        # Block listed countries\n")
		fmt.Fprintf(buf, "        ip saddr @blocked_v4 drop\n")
		fmt.Fprintf(buf, "        ip6 saddr @blocked_v6 drop\n\n")
		fmt.Fprintf(buf, "        # Everything else: accept (policy)\n")
	} else {
		// Rule 4: Allow listed countries, drop the rest for new connections
		fmt.Fprintf(buf, "        # Allow listed countries\n")
		fmt.Fprintf(buf, "        ct state new ip saddr @allowed_v4 accept\n")
		fmt.Fprintf(buf, "        ct state new ip6 saddr @allowed_v6 accept\n\n")
		fmt.Fprintf(buf, "        # Drop all other new connections\n")
		fmt.Fprintf(buf, "        ct state new drop\n")
	}

	fmt.Fprintf(buf, "    }\n")
}

// formatPrefixes formats a list of prefixes as a comma-separated string,
// wrapping at ~80 chars per line for readability.
func formatPrefixes(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return ""
	}

	var buf bytes.Buffer
	lineLen := 0
	for i, p := range prefixes {
		s := p.String()
		if i > 0 {
			buf.WriteString(", ")
			lineLen += 2
		}
		if lineLen+len(s) > 76 {
			buf.WriteString("\n            ")
			lineLen = 12
		}
		buf.WriteString(s)
		lineLen += len(s)
	}
	return buf.String()
}

// Apply writes the ruleset to a temp file and atomically applies it via nft -f.
func (m *Manager) Apply(ruleset string) error {
	// Write to temp file
	tmpFile, err := os.CreateTemp("", "vpsguard-ruleset-*.nft")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(ruleset); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing ruleset: %w", err)
	}
	tmpFile.Close()

	// Apply atomically
	cmd := exec.Command(m.NftBinary, "-f", tmpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f failed: %w: %s", err, stderr.String())
	}

	return nil
}

// Cleanup removes the VPSGuard table from nftables.
func (m *Manager) Cleanup() error {
	cmd := exec.Command(m.NftBinary, "delete", "table", "inet", m.TableName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Ignore error if table doesn't exist
		if strings.Contains(stderr.String(), "No such file or directory") ||
			strings.Contains(stderr.String(), "does not exist") {
			return nil
		}
		return fmt.Errorf("deleting table: %w: %s", err, stderr.String())
	}
	return nil
}

// Verify checks that the VPSGuard table exists and has the expected chain.
func (m *Manager) Verify() error {
	cmd := exec.Command(m.NftBinary, "list", "table", "inet", m.TableName)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("listing table: %w: %s", err, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "chain input") {
		return fmt.Errorf("table %s exists but missing input chain", m.TableName)
	}

	return nil
}

// DryRun generates the ruleset and writes it to the given path (or stdout if path is "-").
func (m *Manager) DryRun(params *RulesetParams, outPath string) error {
	ruleset := m.GenerateRuleset(params)

	if outPath == "-" || outPath == "" {
		fmt.Print(ruleset)
		return nil
	}

	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	return os.WriteFile(outPath, []byte(ruleset), 0644)
}
