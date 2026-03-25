package firewall

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func p(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

// --- Structure generation tests ---

func TestGenerateStructureBlocklist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode: "blocklist",
		WhitelistV4: []netip.Prefix{
			p("10.0.0.0/8"),
			p("192.168.1.1/32"),
		},
		WhitelistV6: []netip.Prefix{
			p("::1/128"),
		},
		GeoV4: []netip.Prefix{p("1.0.0.0/24")}, // ignored in structure
	}

	structure := m.GenerateStructure(params)

	// Table lifecycle
	mustContain(t, structure, "table inet vpsguard {}")
	mustContain(t, structure, "delete table inet vpsguard")

	// Sets exist
	mustContain(t, structure, "set whitelist_v4 {")
	mustContain(t, structure, "set whitelist_v6 {")
	mustContain(t, structure, "set blocked_v4 {")
	mustContain(t, structure, "set blocked_v6 {")

	// Whitelist elements are inline (small sets)
	mustContain(t, structure, "10.0.0.0/8")
	mustContain(t, structure, "192.168.1.1/32")

	// Geo elements are NOT inline (loaded in phase 2)
	mustNotContain(t, structure, "1.0.0.0/24")

	// Chain rules
	mustContain(t, structure, "chain input {")
	mustContain(t, structure, "ct state established,related accept")
	mustContain(t, structure, "iif lo accept")
	mustContain(t, structure, "ip saddr @whitelist_v4 accept")
	mustContain(t, structure, "ip saddr @blocked_v4 drop")
	mustContain(t, structure, "ip6 saddr @blocked_v6 drop")

	// Should NOT contain allowlist-specific constructs
	mustNotContain(t, structure, "allowed_v4")
	mustNotContain(t, structure, "ct state new drop")
}

func TestGenerateStructureAllowlist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode: "allowlist",
		WhitelistV4: []netip.Prefix{
			p("192.168.0.0/16"),
		},
	}

	structure := m.GenerateStructure(params)

	mustContain(t, structure, "set allowed_v4 {")
	mustContain(t, structure, "set allowed_v6 {")
	mustNotContain(t, structure, "blocked_v4")

	mustContain(t, structure, "ct state new ip saddr @allowed_v4 accept")
	mustContain(t, structure, "ct state new ip6 saddr @allowed_v6 accept")
	mustContain(t, structure, "ct state new drop")
}

func TestGenerateStructureEmptySets(t *testing.T) {
	m := NewManager("test_table", 0)
	params := &RulesetParams{
		Mode: "blocklist",
	}

	structure := m.GenerateStructure(params)

	mustContain(t, structure, "set whitelist_v4 {")
	mustContain(t, structure, "set blocked_v4 {")
	mustContain(t, structure, "chain input {")
	mustContain(t, structure, "ct state established,related accept")
}

func TestGenerateStructurePriority(t *testing.T) {
	tests := []struct {
		priority int
		want     string
	}{
		{-1, "priority -1;"},
		{0, "priority 0;"},
		{-10, "priority -10;"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			m := NewManager("vpsguard", tt.priority)
			params := &RulesetParams{Mode: "blocklist"}
			mustContain(t, m.GenerateStructure(params), tt.want)
		})
	}
}

func TestEnsureTableExistsBeforeDelete(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{Mode: "blocklist"}
	structure := m.GenerateStructure(params)

	posEnsure := strings.Index(structure, "table inet vpsguard {}")
	posDelete := strings.Index(structure, "delete table inet vpsguard")
	posCreate := strings.LastIndex(structure, "table inet vpsguard {")

	if posEnsure == -1 {
		t.Fatal("missing ensure-exists line")
	}
	if posDelete == -1 {
		t.Fatal("missing delete table line")
	}
	if posEnsure >= posDelete {
		t.Error("ensure-exists must come BEFORE delete")
	}
	if posDelete >= posCreate {
		t.Error("delete must come BEFORE the actual table creation")
	}
}

func TestTableNameCustom(t *testing.T) {
	m := NewManager("my_custom_table", -5)
	params := &RulesetParams{Mode: "blocklist"}
	structure := m.GenerateStructure(params)

	mustContain(t, structure, "table inet my_custom_table {}")
	mustContain(t, structure, "delete table inet my_custom_table")
	mustContain(t, structure, "priority -5;")
}

// --- Rule order tests ---

func TestRuleOrderBlocklist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{Mode: "blocklist"}
	structure := m.GenerateStructure(params)

	ruleLines := extractChainRules(structure)

	expectedOrder := []string{
		"ct state established,related accept",
		"iif lo accept",
		"ip saddr @whitelist_v4 accept",
		"ip6 saddr @whitelist_v6 accept",
		"ip saddr @blocked_v4 drop",
		"ip6 saddr @blocked_v6 drop",
	}

	if len(ruleLines) != len(expectedOrder) {
		t.Fatalf("got %d rules, want %d\nrules: %v", len(ruleLines), len(expectedOrder), ruleLines)
	}
	for i, want := range expectedOrder {
		if ruleLines[i] != want {
			t.Errorf("rule[%d] = %q, want %q", i, ruleLines[i], want)
		}
	}
}

func TestRuleOrderAllowlist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{Mode: "allowlist"}
	structure := m.GenerateStructure(params)

	ruleLines := extractChainRules(structure)

	expectedOrder := []string{
		"ct state established,related accept",
		"iif lo accept",
		"ip saddr @whitelist_v4 accept",
		"ip6 saddr @whitelist_v6 accept",
		"ct state new ip saddr @allowed_v4 accept",
		"ct state new ip6 saddr @allowed_v6 accept",
		"ct state new drop",
	}

	if len(ruleLines) != len(expectedOrder) {
		t.Fatalf("got %d rules, want %d\nrules: %v", len(ruleLines), len(expectedOrder), ruleLines)
	}
	for i, want := range expectedOrder {
		if ruleLines[i] != want {
			t.Errorf("rule[%d] = %q, want %q", i, ruleLines[i], want)
		}
	}
}

func TestEstablishedRelatedFirst(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{Mode: "blocklist"}
	structure := m.GenerateStructure(params)

	posEstablished := strings.Index(structure, "ct state established,related accept")
	posBlocked := strings.Index(structure, "@blocked_v4 drop")

	if posEstablished == -1 {
		t.Fatal("missing established,related rule")
	}
	if posBlocked == -1 {
		t.Fatal("missing blocked rule")
	}
	if posEstablished >= posBlocked {
		t.Error("established,related rule must come BEFORE geo blocking rules")
	}
}

// --- Element batch tests ---

func TestGenerateElementBatchesSingleBatch(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:  "blocklist",
		GeoV4: []netip.Prefix{p("1.0.0.0/24"), p("2.0.0.0/16")},
		GeoV6: []netip.Prefix{p("2001:200::/32")},
	}

	batches := m.GenerateElementBatches(params)
	if len(batches) != 2 { // one for v4, one for v6
		t.Fatalf("got %d batches, want 2", len(batches))
	}

	mustContain(t, batches[0], "add element inet vpsguard blocked_v4")
	mustContain(t, batches[0], "1.0.0.0/24")
	mustContain(t, batches[0], "2.0.0.0/16")

	mustContain(t, batches[1], "add element inet vpsguard blocked_v6")
	mustContain(t, batches[1], "2001:200::/32")
}

func TestGenerateElementBatchesAllowlist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:  "allowlist",
		GeoV4: []netip.Prefix{p("8.8.8.0/24")},
	}

	batches := m.GenerateElementBatches(params)
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(batches))
	}
	mustContain(t, batches[0], "add element inet vpsguard allowed_v4")
	mustNotContain(t, batches[0], "blocked_v4")
}

func TestGenerateElementBatchesEmpty(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{Mode: "blocklist"}

	batches := m.GenerateElementBatches(params)
	if len(batches) != 0 {
		t.Errorf("got %d batches, want 0 for empty sets", len(batches))
	}
}

func TestGenerateElementBatchesMultipleBatches(t *testing.T) {
	m := NewManager("vpsguard", -1)

	// Create more prefixes than ElementBatchSize
	var prefixes []netip.Prefix
	for i := 0; i < ElementBatchSize+100; i++ {
		a := byte(i / 256)
		b := byte(i % 256)
		prefixes = append(prefixes, netip.MustParsePrefix(
			fmt.Sprintf("%d.%d.0.0/16", a+1, b),
		))
	}

	params := &RulesetParams{
		Mode:  "blocklist",
		GeoV4: prefixes,
	}

	batches := m.GenerateElementBatches(params)

	// Should have at least 2 batches for v4 (600 items / 500 batch = 2)
	if len(batches) < 2 {
		t.Fatalf("got %d batches, want >= 2 for %d prefixes", len(batches), len(prefixes))
	}

	// Every batch should reference the correct set
	for i, batch := range batches {
		mustContain(t, batch, "add element inet vpsguard blocked_v4")
		if len(batch) == 0 {
			t.Errorf("batch %d is empty", i)
		}
	}
}

func TestBatchElementsDirectly(t *testing.T) {
	prefixes := []netip.Prefix{
		p("10.0.0.0/8"),
		p("172.16.0.0/12"),
		p("192.168.0.0/16"),
	}

	batches := batchElements("mytable", "myset", prefixes)
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(batches))
	}
	mustContain(t, batches[0], "add element inet mytable myset")
	mustContain(t, batches[0], "10.0.0.0/8")
	mustContain(t, batches[0], "172.16.0.0/12")
	mustContain(t, batches[0], "192.168.0.0/16")
}

func TestBatchElementsNil(t *testing.T) {
	batches := batchElements("t", "s", nil)
	if batches != nil {
		t.Errorf("got %v, want nil", batches)
	}
}

// --- Combined GenerateRuleset (for dry-run) ---

func TestGenerateRulesetContainsBoth(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:    "blocklist",
		GeoV4:   []netip.Prefix{p("1.0.0.0/24")},
		GeoV6:   []netip.Prefix{p("2001:200::/32")},
		WhitelistV4: []netip.Prefix{p("10.0.0.0/8")},
	}

	ruleset := m.GenerateRuleset(params)

	// Structure parts
	mustContain(t, ruleset, "table inet vpsguard {}")
	mustContain(t, ruleset, "chain input {")
	mustContain(t, ruleset, "set blocked_v4 {")

	// Whitelist inline
	mustContain(t, ruleset, "10.0.0.0/8")

	// Element batches
	mustContain(t, ruleset, "add element inet vpsguard blocked_v4")
	mustContain(t, ruleset, "1.0.0.0/24")
	mustContain(t, ruleset, "add element inet vpsguard blocked_v6")
	mustContain(t, ruleset, "2001:200::/32")
}

func TestNoAutoMerge(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:  "blocklist",
		GeoV4: []netip.Prefix{p("1.0.0.0/8")},
	}
	ruleset := m.GenerateRuleset(params)
	mustNotContain(t, ruleset, "auto-merge")
}

// --- DryRun ---

func TestDryRunToFile(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:  "blocklist",
		GeoV4: []netip.Prefix{p("1.0.0.0/24")},
	}

	outPath := filepath.Join(t.TempDir(), "output.nft")
	if err := m.DryRun(params, outPath); err != nil {
		t.Fatalf("DryRun error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	mustContain(t, string(data), "table inet vpsguard")
	mustContain(t, string(data), "add element")
}

// --- FormatPrefixes ---

func TestFormatPrefixes(t *testing.T) {
	prefixes := []netip.Prefix{p("1.0.0.0/24"), p("2.0.0.0/16"), p("10.0.0.0/8")}
	got := formatPrefixes(prefixes)
	mustContain(t, got, "1.0.0.0/24")
	mustContain(t, got, "2.0.0.0/16")
}

func TestFormatPrefixesEmpty(t *testing.T) {
	if got := formatPrefixes(nil); got != "" {
		t.Errorf("formatPrefixes(nil) = %q, want empty", got)
	}
}

func TestFormatPrefixesWrapping(t *testing.T) {
	var prefixes []netip.Prefix
	for i := 0; i < 30; i++ {
		prefixes = append(prefixes, p("10.0.0.0/8"))
	}
	got := formatPrefixes(prefixes)
	if !strings.Contains(got, "\n") {
		t.Error("expected wrapping for many prefixes")
	}
}

// --- Helpers ---

func extractChainRules(s string) []string {
	lines := strings.Split(s, "\n")
	var ruleLines []string
	inChain := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "chain input {") {
			inChain = true
			continue
		}
		if inChain && trimmed == "}" {
			break
		}
		if inChain && trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "type filter") {
			ruleLines = append(ruleLines, trimmed)
		}
	}
	return ruleLines
}

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("output missing %q", substr)
	}
}

func mustNotContain(t *testing.T, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("output should not contain %q", substr)
	}
}
