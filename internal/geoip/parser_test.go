package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const locationsCSV = `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
2077456,en,OC,Oceania,AU,Australia,0
2750405,en,EU,Europe,NL,Netherlands,1
1814991,en,AS,Asia,CN,China,0
2017370,en,EU,Europe,RU,Russia,0
6252001,en,NA,"North America",US,"United States",0
`

const blocksV4CSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
1.0.0.0/24,2077456,2077456,,0,0,0
1.0.1.0/24,1814991,1814991,,0,0,0
1.0.2.0/23,1814991,1814991,,0,0,0
5.0.0.0/16,2750405,2750405,,0,0,0
8.8.8.0/24,6252001,6252001,,0,0,0
37.0.0.0/16,2017370,2017370,,0,0,0
`

const blocksV6CSV = `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
2001:200::/32,1814991,1814991,,0,0,0
2001:610::/32,2750405,2750405,,0,0,0
2001:4860::/32,6252001,6252001,,0,0,0
2a00::/16,2017370,2017370,,0,0,0
`

func TestParseLocations(t *testing.T) {
	locs, err := ParseLocations(strings.NewReader(locationsCSV))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		geonameID string
		want      string
	}{
		{"2077456", "AU"},
		{"2750405", "NL"},
		{"1814991", "CN"},
		{"2017370", "RU"},
		{"6252001", "US"},
	}
	for _, tt := range tests {
		got, ok := locs[tt.geonameID]
		if !ok {
			t.Errorf("missing geoname_id %s", tt.geonameID)
			continue
		}
		if got != tt.want {
			t.Errorf("locs[%s] = %q, want %q", tt.geonameID, got, tt.want)
		}
	}
}

func TestParseLocationsEmpty(t *testing.T) {
	csv := `geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
`
	_, err := ParseLocations(strings.NewReader(csv))
	if err == nil {
		t.Fatal("expected error for empty locations")
	}
}

func TestParseLocationsMissingColumns(t *testing.T) {
	csv := `id,name
1,test
`
	_, err := ParseLocations(strings.NewReader(csv))
	if err == nil {
		t.Fatal("expected error for missing columns")
	}
}

func TestParseBlocksV4(t *testing.T) {
	locs, _ := ParseLocations(strings.NewReader(locationsCSV))
	target := map[string]bool{"CN": true, "RU": true}

	blocks, err := ParseBlocks(strings.NewReader(blocksV4CSV), locs, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have CN and RU entries
	cnPrefixes, ok := blocks["CN"]
	if !ok {
		t.Fatal("missing CN prefixes")
	}
	if len(cnPrefixes) != 2 {
		t.Errorf("CN has %d prefixes, want 2", len(cnPrefixes))
	}

	ruPrefixes, ok := blocks["RU"]
	if !ok {
		t.Fatal("missing RU prefixes")
	}
	if len(ruPrefixes) != 1 {
		t.Errorf("RU has %d prefixes, want 1", len(ruPrefixes))
	}

	// Should NOT have AU, NL, US (not in target)
	for _, code := range []string{"AU", "NL", "US"} {
		if _, ok := blocks[code]; ok {
			t.Errorf("unexpected country %s in results (should be filtered)", code)
		}
	}
}

func TestParseBlocksV6(t *testing.T) {
	locs, _ := ParseLocations(strings.NewReader(locationsCSV))
	target := map[string]bool{"CN": true}

	blocks, err := ParseBlocks(strings.NewReader(blocksV6CSV), locs, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cnPrefixes, ok := blocks["CN"]
	if !ok {
		t.Fatal("missing CN IPv6 prefixes")
	}
	if len(cnPrefixes) != 1 {
		t.Errorf("CN has %d IPv6 prefixes, want 1", len(cnPrefixes))
	}
	want := netip.MustParsePrefix("2001:200::/32")
	if cnPrefixes[0] != want {
		t.Errorf("CN prefix = %v, want %v", cnPrefixes[0], want)
	}
}

func TestParseBlocksAllCountries(t *testing.T) {
	locs, _ := ParseLocations(strings.NewReader(locationsCSV))

	// nil target means collect all
	blocks, err := ParseBlocks(strings.NewReader(blocksV4CSV), locs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have all 5 countries
	expected := []string{"AU", "CN", "NL", "US", "RU"}
	for _, code := range expected {
		if _, ok := blocks[code]; !ok {
			t.Errorf("missing country %s when target is nil", code)
		}
	}
}

func TestParseBlocksFallbackToRegistered(t *testing.T) {
	// Block with empty geoname_id but valid registered_country_geoname_id
	csv := `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
2.0.0.0/24,,6252001,,0,0,0
`
	locs, _ := ParseLocations(strings.NewReader(locationsCSV))
	target := map[string]bool{"US": true}

	blocks, err := ParseBlocks(strings.NewReader(csv), locs, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	usPrefixes, ok := blocks["US"]
	if !ok {
		t.Fatal("expected US prefix via registered_country fallback")
	}
	if len(usPrefixes) != 1 {
		t.Errorf("US has %d prefixes, want 1", len(usPrefixes))
	}
}

func TestParseBlocksInvalidNetwork(t *testing.T) {
	csv := `network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
not-a-cidr,1814991,1814991,,0,0,0
1.0.0.0/24,1814991,1814991,,0,0,0
`
	locs, _ := ParseLocations(strings.NewReader(locationsCSV))
	target := map[string]bool{"CN": true}

	blocks, err := ParseBlocks(strings.NewReader(csv), locs, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should skip invalid and still parse the valid one
	if len(blocks["CN"]) != 1 {
		t.Errorf("CN has %d prefixes, want 1 (invalid should be skipped)", len(blocks["CN"]))
	}
}

func TestLoadFromDir(t *testing.T) {
	dir := t.TempDir()

	// Write test CSV files
	writeFile(t, dir, "GeoLite2-Country-Locations-en.csv", locationsCSV)
	writeFile(t, dir, "GeoLite2-Country-Blocks-IPv4.csv", blocksV4CSV)
	writeFile(t, dir, "GeoLite2-Country-Blocks-IPv6.csv", blocksV6CSV)

	cidrs, err := LoadFromDir(dir, []string{"CN", "RU"})
	if err != nil {
		t.Fatalf("LoadFromDir error: %v", err)
	}

	// Check V4
	if len(cidrs.V4["CN"]) != 2 {
		t.Errorf("CN IPv4 = %d, want 2", len(cidrs.V4["CN"]))
	}
	if len(cidrs.V4["RU"]) != 1 {
		t.Errorf("RU IPv4 = %d, want 1", len(cidrs.V4["RU"]))
	}

	// Check V6
	if len(cidrs.V6["CN"]) != 1 {
		t.Errorf("CN IPv6 = %d, want 1", len(cidrs.V6["CN"]))
	}
	if len(cidrs.V6["RU"]) != 1 {
		t.Errorf("RU IPv6 = %d, want 1", len(cidrs.V6["RU"]))
	}
}

func TestLoadFromDirMissingFile(t *testing.T) {
	dir := t.TempDir()
	// Only create locations file, missing blocks files
	writeFile(t, dir, "GeoLite2-Country-Locations-en.csv", locationsCSV)

	_, err := LoadFromDir(dir, []string{"CN"})
	if err == nil {
		t.Fatal("expected error for missing blocks file")
	}
}

func TestStats(t *testing.T) {
	cidrs := NewCountryCIDRs()
	cidrs.V4["CN"] = []netip.Prefix{
		netip.MustParsePrefix("1.0.0.0/24"),
		netip.MustParsePrefix("1.0.1.0/24"),
	}
	cidrs.V6["CN"] = []netip.Prefix{
		netip.MustParsePrefix("2001:200::/32"),
	}
	cidrs.V4["RU"] = []netip.Prefix{
		netip.MustParsePrefix("37.0.0.0/16"),
	}

	stats := cidrs.Stats()
	if stats["CN"] != [2]int{2, 1} {
		t.Errorf("CN stats = %v, want [2 1]", stats["CN"])
	}
	if stats["RU"] != [2]int{1, 0} {
		t.Errorf("RU stats = %v, want [1 0]", stats["RU"])
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}
