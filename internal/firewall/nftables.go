// Package firewall generates and applies nftables rulesets for VPSGuard.
//
// The ruleset is applied in two phases to work around kernel netlink message
// size limits when loading large GeoIP sets (40k+ CIDRs):
//
//   Phase 1: Create table structure (empty sets + chain rules)
//   Phase 2: Populate sets in batches via "add element" commands
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

// ElementBatchSize controls how many CIDRs are loaded per nft add element call.
// 500 is conservative enough for any kernel netlink buffer size.
const ElementBatchSize = 500

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
	Mode        string         // "blocklist" or "allowlist"
	WhitelistV4 []netip.Prefix // IPv4 whitelist CIDRs
	WhitelistV6 []netip.Prefix // IPv6 whitelist CIDRs
	GeoV4       []netip.Prefix // IPv4 country CIDRs (meaning depends on mode)
	GeoV6       []netip.Prefix // IPv6 country CIDRs
}

// --- Phase 1: Table structure (empty sets + chain) ---

// GenerateStructure produces the nftables table with empty sets and chain rules.
// This is small and always succeeds with nft -f.
func (m *Manager) GenerateStructure(params *RulesetParams) string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "# VPSGuard nftables ruleset - auto-generated\n")
	fmt.Fprintf(&buf, "# Mode: %s\n\n", params.Mode)

	// Ensure table exists then delete (safe for first run)
	fmt.Fprintf(&buf, "table inet %s {}\n", m.TableName)
	fmt.Fprintf(&buf, "delete table inet %s\n\n", m.TableName)

	fmt.Fprintf(&buf, "table inet %s {\n", m.TableName)

	// Whitelist sets — small, inline elements are fine
	m.writeSet(&buf, "whitelist_v4", "ipv4_addr", params.WhitelistV4)
	m.writeSet(&buf, "whitelist_v6", "ipv6_addr", params.WhitelistV6)

	// Geo sets — empty here, populated in phase 2
	if params.Mode == "blocklist" {
		m.writeEmptySet(&buf, "blocked_v4", "ipv4_addr")
		m.writeEmptySet(&buf, "blocked_v6", "ipv6_addr")
	} else {
		m.writeEmptySet(&buf, "allowed_v4", "ipv4_addr")
		m.writeEmptySet(&buf, "allowed_v6", "ipv6_addr")
	}

	m.writeChain(&buf, params.Mode)

	fmt.Fprintf(&buf, "}\n")
	return buf.String()
}

// --- Phase 2: Batched element loading ---

// GenerateElementBatches produces a list of nft script snippets, each adding
// up to ElementBatchSize CIDRs to a set. Each snippet can be applied with nft -f.
func (m *Manager) GenerateElementBatches(params *RulesetParams) []string {
	var batches []string

	geoV4Set := "blocked_v4"
	geoV6Set := "blocked_v6"
	if params.Mode == "allowlist" {
		geoV4Set = "allowed_v4"
		geoV6Set = "allowed_v6"
	}

	batches = append(batches, batchElements(m.TableName, geoV4Set, params.GeoV4)...)
	batches = append(batches, batchElements(m.TableName, geoV6Set, params.GeoV6)...)

	return batches
}

// batchElements splits prefixes into batches and generates "add element" statements.
func batchElements(table, set string, prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}

	var batches []string
	for i := 0; i < len(prefixes); i += ElementBatchSize {
		end := i + ElementBatchSize
		if end > len(prefixes) {
			end = len(prefixes)
		}
		chunk := prefixes[i:end]

		var buf bytes.Buffer
		fmt.Fprintf(&buf, "add element inet %s %s { ", table, set)
		for j, p := range chunk {
			if j > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(p.String())
		}
		buf.WriteString(" }\n")
		batches = append(batches, buf.String())
	}
	return batches
}

// --- Combined: GenerateRuleset for dry-run / display ---

// GenerateRuleset produces the complete ruleset as a single string (for dry-run display).
// Note: this single-file format may fail with nft -f for large sets; Apply() uses
// the two-phase approach instead.
func (m *Manager) GenerateRuleset(params *RulesetParams) string {
	var buf bytes.Buffer

	// Phase 1
	buf.WriteString(m.GenerateStructure(params))
	buf.WriteString("\n")

	// Phase 2
	for _, batch := range m.GenerateElementBatches(params) {
		buf.WriteString(batch)
	}

	return buf.String()
}

// --- Set helpers ---

func (m *Manager) writeSet(buf *bytes.Buffer, name, addrType string, prefixes []netip.Prefix) {
	fmt.Fprintf(buf, "    set %s {\n", name)
	fmt.Fprintf(buf, "        type %s\n", addrType)
	fmt.Fprintf(buf, "        flags interval\n")
	if len(prefixes) > 0 {
		fmt.Fprintf(buf, "        elements = { %s }\n", formatPrefixes(prefixes))
	}
	fmt.Fprintf(buf, "    }\n\n")
}

func (m *Manager) writeEmptySet(buf *bytes.Buffer, name, addrType string) {
	fmt.Fprintf(buf, "    set %s {\n", name)
	fmt.Fprintf(buf, "        type %s\n", addrType)
	fmt.Fprintf(buf, "        flags interval\n")
	fmt.Fprintf(buf, "    }\n\n")
}

// --- Chain ---

func (m *Manager) writeChain(buf *bytes.Buffer, mode string) {
	fmt.Fprintf(buf, "    chain input {\n")
	fmt.Fprintf(buf, "        type filter hook input priority %d; policy accept;\n\n", m.Priority)

	fmt.Fprintf(buf, "        # Allow established/related connections (ensures outbound traffic works)\n")
	fmt.Fprintf(buf, "        ct state established,related accept\n\n")

	fmt.Fprintf(buf, "        # Allow loopback\n")
	fmt.Fprintf(buf, "        iif lo accept\n\n")

	fmt.Fprintf(buf, "        # Whitelist always passes\n")
	fmt.Fprintf(buf, "        ip saddr @whitelist_v4 accept\n")
	fmt.Fprintf(buf, "        ip6 saddr @whitelist_v6 accept\n\n")

	if mode == "blocklist" {
		fmt.Fprintf(buf, "        # Block listed countries\n")
		fmt.Fprintf(buf, "        ip saddr @blocked_v4 drop\n")
		fmt.Fprintf(buf, "        ip6 saddr @blocked_v6 drop\n\n")
		fmt.Fprintf(buf, "        # Everything else: accept (policy)\n")
	} else {
		fmt.Fprintf(buf, "        # Allow listed countries\n")
		fmt.Fprintf(buf, "        ct state new ip saddr @allowed_v4 accept\n")
		fmt.Fprintf(buf, "        ct state new ip6 saddr @allowed_v6 accept\n\n")
		fmt.Fprintf(buf, "        # Drop all other new connections\n")
		fmt.Fprintf(buf, "        ct state new drop\n")
	}

	fmt.Fprintf(buf, "    }\n")
}

// --- Formatting ---

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

// --- Apply (two-phase) ---

// Apply creates the table structure, then populates sets in batches.
func (m *Manager) Apply(params *RulesetParams) error {
	// Phase 1: structure
	structure := m.GenerateStructure(params)
	if err := m.nftExecString(structure); err != nil {
		return fmt.Errorf("applying table structure: %w", err)
	}

	// Phase 2: elements in batches
	batches := m.GenerateElementBatches(params)
	for i, batch := range batches {
		if err := m.nftExecString(batch); err != nil {
			return fmt.Errorf("loading element batch %d/%d: %w", i+1, len(batches), err)
		}
	}

	return nil
}

// nftExecString writes content to a temp file and runs nft -f on it.
func (m *Manager) nftExecString(content string) error {
	tmpFile, err := os.CreateTemp("", "vpsguard-*.nft")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	tmpFile.Close()

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

// DryRun generates the full ruleset and writes it to the given path (or stdout).
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
