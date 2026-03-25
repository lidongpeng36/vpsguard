package geoip

import (
	"net/netip"
	"os"
	"testing"
)

func TestMergePrefixes(t *testing.T) {
	input := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"),
		netip.MustParsePrefix("10.0.0.128/25"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}

	got, err := mergePrefixes(input)
	if err != nil {
		t.Fatalf("mergePrefixes error: %v", err)
	}

	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/23"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestLoadFromDirUsesOptimizedCache(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "GeoLite2-Country-Locations-en.csv", locationsCSV)
	writeFile(t, dir, "GeoLite2-Country-Blocks-IPv4.csv", blocksV4CSV)
	writeFile(t, dir, "GeoLite2-Country-Blocks-IPv6.csv", blocksV6CSV)

	countries := []string{"CN"}
	first, err := LoadFromDir(dir, countries)
	if err != nil {
		t.Fatalf("first LoadFromDir: %v", err)
	}

	cachePath, err := optimizedCachePath(dir, countries)
	if err != nil {
		t.Fatalf("optimizedCachePath: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache file at %s: %v", cachePath, err)
	}

	second, err := LoadFromDir(dir, countries)
	if err != nil {
		t.Fatalf("second LoadFromDir: %v", err)
	}

	if len(first.V4["CN"]) != len(second.V4["CN"]) || len(first.V6["CN"]) != len(second.V6["CN"]) {
		t.Fatalf("cache result mismatch: first=%v second=%v", first.Stats(), second.Stats())
	}

	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file disappeared: %v", err)
	}
}
