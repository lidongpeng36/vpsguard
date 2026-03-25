// Package firewall generates and applies nftables rulesets for VPSGuard.
//
// The human-readable ruleset text is still generated for dry-run output, but
// live changes are applied through github.com/google/nftables over netlink.
package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ElementBatchSize controls how many CIDRs are loaded per netlink batch.
// 500 is conservative enough for large GeoIP sets.
const ElementBatchSize = 500

const (
	reg1 = 1
)

// Manager handles nftables rule generation and application.
type Manager struct {
	TableName string
	Priority  int
}

// NewManager creates a Manager with sensible defaults.
func NewManager(tableName string, priority int) *Manager {
	return &Manager{
		TableName: tableName,
		Priority:  priority,
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
func (m *Manager) GenerateStructure(params *RulesetParams) string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "# VPSGuard nftables ruleset - auto-generated\n")
	fmt.Fprintf(&buf, "# Mode: %s\n\n", params.Mode)

	// Ensure table exists then delete (safe for first run)
	fmt.Fprintf(&buf, "table inet %s {}\n", m.TableName)
	fmt.Fprintf(&buf, "delete table inet %s\n\n", m.TableName)

	fmt.Fprintf(&buf, "table inet %s {\n", m.TableName)

	m.writeSet(&buf, "whitelist_v4", "ipv4_addr", params.WhitelistV4)
	m.writeSet(&buf, "whitelist_v6", "ipv6_addr", params.WhitelistV6)

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

// GenerateRuleset produces the complete ruleset as a single string.
func (m *Manager) GenerateRuleset(params *RulesetParams) string {
	var buf bytes.Buffer

	buf.WriteString(m.GenerateStructure(params))
	buf.WriteString("\n")

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

// --- Apply (netlink) ---

// Apply recreates the managed table, then populates large GeoIP sets in batches.
func (m *Manager) Apply(params *RulesetParams) error {
	conn := &nftables.Conn{}
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   m.TableName,
	}

	if existing, err := conn.ListTableOfFamily(m.TableName, nftables.TableFamilyINet); err == nil && existing != nil {
		conn.DelTable(existing)
	}

	table = conn.AddTable(table)

	chain := conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(nftables.ChainPriority(m.Priority)),
		Policy:   chainPolicyRef(nftables.ChainPolicyAccept),
	})

	if err := m.addManagedSets(conn, table, params); err != nil {
		return fmt.Errorf("creating sets: %w", err)
	}

	m.addRules(conn, table, chain, params.Mode)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flushing table structure: %w", err)
	}

	if err := m.populateGeoSets(params); err != nil {
		return fmt.Errorf("loading GeoIP sets: %w", err)
	}

	return nil
}

func (m *Manager) addManagedSets(conn *nftables.Conn, table *nftables.Table, params *RulesetParams) error {
	whitelistV4 := newAddrSet(table, "whitelist_v4", nftables.TypeIPAddr)
	whitelistV6 := newAddrSet(table, "whitelist_v6", nftables.TypeIP6Addr)
	if err := conn.AddSet(whitelistV4, prefixesToElements(params.WhitelistV4)); err != nil {
		return err
	}
	if err := conn.AddSet(whitelistV6, prefixesToElements(params.WhitelistV6)); err != nil {
		return err
	}

	geoV4Name := "blocked_v4"
	geoV6Name := "blocked_v6"
	if params.Mode == "allowlist" {
		geoV4Name = "allowed_v4"
		geoV6Name = "allowed_v6"
	}

	if err := conn.AddSet(newAddrSet(table, geoV4Name, nftables.TypeIPAddr), nil); err != nil {
		return err
	}
	if err := conn.AddSet(newAddrSet(table, geoV6Name, nftables.TypeIP6Addr), nil); err != nil {
		return err
	}

	return nil
}

func (m *Manager) populateGeoSets(params *RulesetParams) error {
	geoV4Name := "blocked_v4"
	geoV6Name := "blocked_v6"
	if params.Mode == "allowlist" {
		geoV4Name = "allowed_v4"
		geoV6Name = "allowed_v6"
	}

	if err := m.addSetElementsInBatches(geoV4Name, nftables.TypeIPAddr, params.GeoV4); err != nil {
		return err
	}
	if err := m.addSetElementsInBatches(geoV6Name, nftables.TypeIP6Addr, params.GeoV6); err != nil {
		return err
	}
	return nil
}

func (m *Manager) addSetElementsInBatches(name string, dataType nftables.SetDatatype, prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return nil
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   m.TableName,
	}

	for i := 0; i < len(prefixes); i += ElementBatchSize {
		end := i + ElementBatchSize
		if end > len(prefixes) {
			end = len(prefixes)
		}

		conn := &nftables.Conn{}
		set, err := conn.GetSetByName(table, name)
		if err != nil {
			return fmt.Errorf("looking up set %s: %w", name, err)
		}
		set.KeyType = dataType
		set.Interval = true

		if err := conn.SetAddElements(set, prefixesToElements(prefixes[i:end])); err != nil {
			return fmt.Errorf("queueing batch %d-%d for %s: %w", i, end, name, err)
		}
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("flushing batch %d-%d for %s: %w", i, end, name, err)
		}
	}

	return nil
}

func (m *Manager) addRules(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, mode string) {
	conn.AddRule(ruleEstablishedRelated(table, chain))
	conn.AddRule(ruleLoopback(table, chain))
	conn.AddRule(ruleLookupV4(table, chain, "whitelist_v4", nil, expr.VerdictAccept))
	conn.AddRule(ruleLookupV6(table, chain, "whitelist_v6", nil, expr.VerdictAccept))

	if mode == "blocklist" {
		conn.AddRule(ruleLookupV4(table, chain, "blocked_v4", nil, expr.VerdictDrop))
		conn.AddRule(ruleLookupV6(table, chain, "blocked_v6", nil, expr.VerdictDrop))
		return
	}

	newState := ctStateMatchExprs(expr.CtStateBitNEW)
	conn.AddRule(ruleLookupV4(table, chain, "allowed_v4", newState, expr.VerdictAccept))
	conn.AddRule(ruleLookupV6(table, chain, "allowed_v6", newState, expr.VerdictAccept))
	conn.AddRule(ruleWithExprs(table, chain, append(newState, verdictExpr(expr.VerdictDrop))...))
}

func newAddrSet(table *nftables.Table, name string, dataType nftables.SetDatatype) *nftables.Set {
	return &nftables.Set{
		Table:    table,
		Name:     name,
		KeyType:  dataType,
		Interval: true,
	}
}

func ruleEstablishedRelated(table *nftables.Table, chain *nftables.Chain) *nftables.Rule {
	mask := expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	exprs := append(ctStateMatchExprs(mask), verdictExpr(expr.VerdictAccept))
	return ruleWithExprs(table, chain, exprs...)
}

func ruleLoopback(table *nftables.Table, chain *nftables.Chain) *nftables.Rule {
	return ruleWithExprs(table, chain,
		&expr.Meta{
			Key:      expr.MetaKeyIIFNAME,
			Register: reg1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: reg1,
			Data:     ifName("lo"),
		},
		verdictExpr(expr.VerdictAccept),
	)
}

func ruleLookupV4(table *nftables.Table, chain *nftables.Chain, setName string, prefix []expr.Any, verdict expr.VerdictKind) *nftables.Rule {
	exprs := make([]expr.Any, 0, len(prefix)+3)
	exprs = append(exprs, prefix...)
	exprs = append(exprs,
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  reg1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        12,
			Len:           4,
		},
		&expr.Lookup{
			SourceRegister: reg1,
			SetName:        setName,
		},
		verdictExpr(verdict),
	)
	return ruleWithExprs(table, chain, exprs...)
}

func ruleLookupV6(table *nftables.Table, chain *nftables.Chain, setName string, prefix []expr.Any, verdict expr.VerdictKind) *nftables.Rule {
	exprs := make([]expr.Any, 0, len(prefix)+3)
	exprs = append(exprs, prefix...)
	exprs = append(exprs,
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  reg1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        8,
			Len:           16,
		},
		&expr.Lookup{
			SourceRegister: reg1,
			SetName:        setName,
		},
		verdictExpr(verdict),
	)
	return ruleWithExprs(table, chain, exprs...)
}

func ruleWithExprs(table *nftables.Table, chain *nftables.Chain, exprs ...expr.Any) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}
}

func verdictExpr(kind expr.VerdictKind) *expr.Verdict {
	return &expr.Verdict{Kind: kind}
}

func ctStateMatchExprs(mask uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Register: reg1,
			Key:      expr.CtKeySTATE,
		},
		&expr.Bitwise{
			SourceRegister: reg1,
			DestRegister:   reg1,
			Len:            4,
			Mask:           nativeUint32(mask),
			Xor:            nativeUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: reg1,
			Data:     nativeUint32(0),
		},
	}
}

func ifName(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

func chainPolicyRef(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}

// Cleanup removes the VPSGuard table from nftables.
func (m *Manager) Cleanup() error {
	conn := &nftables.Conn{}

	table, err := conn.ListTableOfFamily(m.TableName, nftables.TableFamilyINet)
	if err != nil {
		if isNotFoundErr(err) {
			return nil
		}
		return fmt.Errorf("listing table: %w", err)
	}
	if table == nil {
		return nil
	}

	conn.DelTable(table)
	if err := conn.Flush(); err != nil && !isNotFoundErr(err) {
		return fmt.Errorf("deleting table: %w", err)
	}
	return nil
}

// Verify checks that the VPSGuard table exists and has the expected chain.
func (m *Manager) Verify() error {
	conn := &nftables.Conn{}

	table, err := conn.ListTableOfFamily(m.TableName, nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("listing table: %w", err)
	}
	if table == nil {
		return fmt.Errorf("table %s not found", m.TableName)
	}

	chain, err := conn.ListChain(table, "input")
	if err != nil {
		return fmt.Errorf("listing input chain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("table %s exists but missing input chain", m.TableName)
	}

	return nil
}

func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file") || strings.Contains(msg, "not found")
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
