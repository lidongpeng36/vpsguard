package firewall

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func p(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func TestGenerateRulesetBlocklist(t *testing.T) {
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
		GeoV4: []netip.Prefix{
			p("1.0.0.0/24"),
			p("1.0.1.0/24"),
		},
		GeoV6: []netip.Prefix{
			p("2001:200::/32"),
		},
	}

	ruleset := m.GenerateRuleset(params)

	// Structure checks
	mustContain(t, ruleset, "delete table inet vpsguard")
	mustContain(t, ruleset, "table inet vpsguard {")
	mustContain(t, ruleset, "set whitelist_v4 {")
	mustContain(t, ruleset, "set whitelist_v6 {")
	mustContain(t, ruleset, "set blocked_v4 {")
	mustContain(t, ruleset, "set blocked_v6 {")
	mustContain(t, ruleset, "chain input {")

	// Rule order checks
	mustContain(t, ruleset, "ct state established,related accept")
	mustContain(t, ruleset, "iif lo accept")
	mustContain(t, ruleset, "ip saddr @whitelist_v4 accept")
	mustContain(t, ruleset, "ip6 saddr @whitelist_v6 accept")
	mustContain(t, ruleset, "ip saddr @blocked_v4 drop")
	mustContain(t, ruleset, "ip6 saddr @blocked_v6 drop")

	// Set elements
	mustContain(t, ruleset, "10.0.0.0/8")
	mustContain(t, ruleset, "192.168.1.1/32")
	mustContain(t, ruleset, "1.0.0.0/24")

	// Should NOT contain allowlist-specific rules
	mustNotContain(t, ruleset, "allowed_v4")
	mustNotContain(t, ruleset, "allowed_v6")
	mustNotContain(t, ruleset, "ct state new drop")
}

func TestGenerateRulesetAllowlist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode: "allowlist",
		WhitelistV4: []netip.Prefix{
			p("192.168.0.0/16"),
		},
		WhitelistV6: nil,
		GeoV4: []netip.Prefix{
			p("8.8.8.0/24"),
		},
		GeoV6: []netip.Prefix{
			p("2001:4860::/32"),
		},
	}

	ruleset := m.GenerateRuleset(params)

	// Should have allowlist sets, not blocklist
	mustContain(t, ruleset, "set allowed_v4 {")
	mustContain(t, ruleset, "set allowed_v6 {")
	mustNotContain(t, ruleset, "blocked_v4")
	mustNotContain(t, ruleset, "blocked_v6")

	// Allowlist-specific rules
	mustContain(t, ruleset, "ct state new ip saddr @allowed_v4 accept")
	mustContain(t, ruleset, "ct state new ip6 saddr @allowed_v6 accept")
	mustContain(t, ruleset, "ct state new drop")
}

func TestGenerateRulesetEmptySets(t *testing.T) {
	m := NewManager("test_table", 0)
	params := &RulesetParams{
		Mode:        "blocklist",
		WhitelistV4: nil,
		WhitelistV6: nil,
		GeoV4:       nil,
		GeoV6:       nil,
	}

	ruleset := m.GenerateRuleset(params)

	// Sets should exist but be empty (no "elements" line)
	mustContain(t, ruleset, "set whitelist_v4 {")
	mustContain(t, ruleset, "set blocked_v4 {")

	// Should still have the chain
	mustContain(t, ruleset, "chain input {")
	mustContain(t, ruleset, "ct state established,related accept")
}

func TestGenerateRulesetPriority(t *testing.T) {
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
			ruleset := m.GenerateRuleset(params)
			mustContain(t, ruleset, tt.want)
		})
	}
}

func TestRuleOrderBlocklist(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:    "blocklist",
		GeoV4:   []netip.Prefix{p("1.0.0.0/8")},
	}
	ruleset := m.GenerateRuleset(params)

	// Verify rule order within the chain
	lines := strings.Split(ruleset, "\n")
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

	// Expected order:
	// 1. ct state established,related accept
	// 2. iif lo accept
	// 3. whitelist accept
	// 4. blocked drop
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
	params := &RulesetParams{
		Mode:    "allowlist",
		GeoV4:   []netip.Prefix{p("8.8.0.0/16")},
	}
	ruleset := m.GenerateRuleset(params)

	lines := strings.Split(ruleset, "\n")
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

func TestFormatPrefixes(t *testing.T) {
	prefixes := []netip.Prefix{
		p("1.0.0.0/24"),
		p("2.0.0.0/16"),
		p("10.0.0.0/8"),
	}
	got := formatPrefixes(prefixes)
	if !strings.Contains(got, "1.0.0.0/24") {
		t.Errorf("missing prefix in formatted output: %s", got)
	}
	if !strings.Contains(got, "2.0.0.0/16") {
		t.Errorf("missing prefix in formatted output: %s", got)
	}
}

func TestFormatPrefixesEmpty(t *testing.T) {
	got := formatPrefixes(nil)
	if got != "" {
		t.Errorf("formatPrefixes(nil) = %q, want empty", got)
	}
}

func TestFormatPrefixesWrapping(t *testing.T) {
	// Many prefixes should wrap to multiple lines
	var prefixes []netip.Prefix
	for i := 0; i < 30; i++ {
		prefixes = append(prefixes, p("10.0.0.0/8"))
	}
	got := formatPrefixes(prefixes)
	if !strings.Contains(got, "\n") {
		t.Error("expected wrapping for many prefixes")
	}
}

func TestDryRunToFile(t *testing.T) {
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode: "blocklist",
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
}

func TestTableNameCustom(t *testing.T) {
	m := NewManager("my_custom_table", -5)
	params := &RulesetParams{Mode: "blocklist"}
	ruleset := m.GenerateRuleset(params)

	mustContain(t, ruleset, "table inet my_custom_table")
	mustContain(t, ruleset, "delete table inet my_custom_table")
	mustContain(t, ruleset, "priority -5;")
}

func TestEstablishedRelatedFirst(t *testing.T) {
	// This test verifies requirement 3:
	// VPS-initiated outbound connections get return traffic through established,related
	// which is the FIRST rule in the chain, before any geo blocking
	m := NewManager("vpsguard", -1)
	params := &RulesetParams{
		Mode:  "blocklist",
		GeoV4: []netip.Prefix{p("1.0.0.0/8")},
	}
	ruleset := m.GenerateRuleset(params)

	// Find positions
	posEstablished := strings.Index(ruleset, "ct state established,related accept")
	posBlocked := strings.Index(ruleset, "@blocked_v4 drop")

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

// Helpers

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
