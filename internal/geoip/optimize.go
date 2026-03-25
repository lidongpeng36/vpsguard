package geoip

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go4.org/netipx"
)

type optimizedCacheFile struct {
	V4 map[string][]string `json:"v4"`
	V6 map[string][]string `json:"v6"`
}

func loadOptimizedFromCache(dir string, countries []string) (*CountryCIDRs, bool, error) {
	path, err := optimizedCachePath(dir, countries)
	if err != nil {
		return nil, false, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reading optimized cache: %w", err)
	}

	var raw optimizedCacheFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, fmt.Errorf("parsing optimized cache: %w", err)
	}

	return &CountryCIDRs{
		V4: parsePrefixMap(raw.V4),
		V6: parsePrefixMap(raw.V6),
	}, true, nil
}

func saveOptimizedToCache(dir string, countries []string, cidrs *CountryCIDRs) error {
	path, err := optimizedCachePath(dir, countries)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating optimized cache dir: %w", err)
	}

	raw := optimizedCacheFile{
		V4: stringifyPrefixMap(cidrs.V4),
		V6: stringifyPrefixMap(cidrs.V6),
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("encoding optimized cache: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing optimized cache: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming optimized cache: %w", err)
	}
	return nil
}

func optimizeCountryCIDRs(cidrs *CountryCIDRs) (*CountryCIDRs, error) {
	optimized := NewCountryCIDRs()

	for country, prefixes := range cidrs.V4 {
		merged, err := mergePrefixes(prefixes)
		if err != nil {
			return nil, fmt.Errorf("optimizing IPv4 prefixes for %s: %w", country, err)
		}
		optimized.V4[country] = merged
	}
	for country, prefixes := range cidrs.V6 {
		merged, err := mergePrefixes(prefixes)
		if err != nil {
			return nil, fmt.Errorf("optimizing IPv6 prefixes for %s: %w", country, err)
		}
		optimized.V6[country] = merged
	}

	return optimized, nil
}

func mergePrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}

	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix.Masked())
	}

	set, err := builder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("building IP set: %w", err)
	}

	merged := set.Prefixes()
	sort.Slice(merged, func(i, j int) bool {
		return netipx.ComparePrefix(merged[i], merged[j]) < 0
	})
	return merged, nil
}

func optimizedCachePath(dir string, countries []string) (string, error) {
	key, err := optimizedCacheKey(dir, countries)
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(filepath.Dir(dir), "optimized")
	return filepath.Join(cacheDir, key+".json"), nil
}

func optimizedCacheKey(dir string, countries []string) (string, error) {
	files := []string{
		"GeoLite2-Country-Locations-en.csv",
		"GeoLite2-Country-Blocks-IPv4.csv",
		"GeoLite2-Country-Blocks-IPv6.csv",
	}

	var parts []string
	parts = append(parts, "v1")
	parts = append(parts, "dir="+filepath.Clean(dir))
	for _, name := range files {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", name, err)
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", name, info.Size(), info.ModTime().UnixNano()))
	}

	sortedCountries := append([]string(nil), countries...)
	sort.Strings(sortedCountries)
	parts = append(parts, "countries="+strings.Join(sortedCountries, ","))

	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:]), nil
}

func stringifyPrefixMap(src map[string][]netip.Prefix) map[string][]string {
	dst := make(map[string][]string, len(src))
	for country, prefixes := range src {
		out := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			out = append(out, prefix.String())
		}
		dst[country] = out
	}
	return dst
}

func parsePrefixMap(src map[string][]string) map[string][]netip.Prefix {
	dst := make(map[string][]netip.Prefix, len(src))
	for country, prefixes := range src {
		out := make([]netip.Prefix, 0, len(prefixes))
		for _, prefix := range prefixes {
			if p, err := netip.ParsePrefix(prefix); err == nil {
				out = append(out, p)
			}
		}
		dst[country] = out
	}
	return dst
}
