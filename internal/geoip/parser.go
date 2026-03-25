// Package geoip handles downloading and parsing MaxMind GeoLite2 CSV data
// to extract CIDR ranges grouped by country.
package geoip

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// CountryCIDRs maps ISO country codes (e.g. "CN", "RU") to their CIDR prefixes.
type CountryCIDRs struct {
	V4 map[string][]netip.Prefix // country code → IPv4 CIDRs
	V6 map[string][]netip.Prefix // country code → IPv6 CIDRs
}

// NewCountryCIDRs creates an empty CountryCIDRs.
func NewCountryCIDRs() *CountryCIDRs {
	return &CountryCIDRs{
		V4: make(map[string][]netip.Prefix),
		V6: make(map[string][]netip.Prefix),
	}
}

// ParseLocations reads GeoLite2-Country-Locations-en.csv and returns a mapping
// from geoname_id to country_iso_code.
//
// CSV format:
//
//	geoname_id, locale_code, continent_code, continent_name, country_iso_code, country_name, is_in_european_union
func ParseLocations(r io.Reader) (map[string]string, error) {
	reader := csv.NewReader(r)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading locations header: %w", err)
	}

	// Find column indices
	geonameIdx := -1
	countryIdx := -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case "geoname_id":
			geonameIdx = i
		case "country_iso_code":
			countryIdx = i
		}
	}
	if geonameIdx == -1 || countryIdx == -1 {
		return nil, fmt.Errorf("locations CSV missing required columns (geoname_id, country_iso_code), found: %v", header)
	}

	locations := make(map[string]string)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading locations row: %w", err)
		}
		if geonameIdx >= len(record) || countryIdx >= len(record) {
			continue
		}
		geonameID := strings.TrimSpace(record[geonameIdx])
		countryCode := strings.TrimSpace(record[countryIdx])
		if geonameID != "" && countryCode != "" {
			locations[geonameID] = countryCode
		}
	}

	if len(locations) == 0 {
		return nil, fmt.Errorf("no valid location entries found")
	}

	return locations, nil
}

// ParseBlocks reads a GeoLite2-Country-Blocks CSV (IPv4 or IPv6) and extracts
// CIDR prefixes for the specified target countries.
//
// CSV format:
//
//	network, geoname_id, registered_country_geoname_id, represented_country_geoname_id, ...
//
// We use geoname_id first, falling back to registered_country_geoname_id.
func ParseBlocks(r io.Reader, locations map[string]string, targetCountries map[string]bool) (map[string][]netip.Prefix, error) {
	reader := csv.NewReader(r)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading blocks header: %w", err)
	}

	networkIdx := -1
	geonameIdx := -1
	regGeonameIdx := -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case "network":
			networkIdx = i
		case "geoname_id":
			geonameIdx = i
		case "registered_country_geoname_id":
			regGeonameIdx = i
		}
	}
	if networkIdx == -1 {
		return nil, fmt.Errorf("blocks CSV missing 'network' column, found: %v", header)
	}

	result := make(map[string][]netip.Prefix)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading blocks row: %w", err)
		}
		if networkIdx >= len(record) {
			continue
		}

		network := strings.TrimSpace(record[networkIdx])
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			continue // skip invalid entries
		}

		// Resolve country: try geoname_id first, then registered_country_geoname_id
		country := ""
		if geonameIdx >= 0 && geonameIdx < len(record) {
			gid := strings.TrimSpace(record[geonameIdx])
			if gid != "" {
				country = locations[gid]
			}
		}
		if country == "" && regGeonameIdx >= 0 && regGeonameIdx < len(record) {
			gid := strings.TrimSpace(record[regGeonameIdx])
			if gid != "" {
				country = locations[gid]
			}
		}

		if country == "" {
			continue
		}

		// Only collect if this country is one we care about (or collect all if targetCountries is nil)
		if targetCountries == nil || targetCountries[country] {
			result[country] = append(result[country], prefix)
		}
	}

	return result, nil
}

// LoadFromDir reads MaxMind CSV files from a directory and returns
// CIDRs for the specified countries. The directory should contain:
//   - GeoLite2-Country-Locations-en.csv
//   - GeoLite2-Country-Blocks-IPv4.csv
//   - GeoLite2-Country-Blocks-IPv6.csv
func LoadFromDir(dir string, countries []string) (*CountryCIDRs, error) {
	if cidrs, ok, err := loadOptimizedFromCache(dir, countries); err != nil {
		return nil, err
	} else if ok {
		return cidrs, nil
	}

	// Build target set
	var targetSet map[string]bool
	if countries != nil {
		targetSet = make(map[string]bool, len(countries))
		for _, c := range countries {
			targetSet[strings.ToUpper(c)] = true
		}
	}

	// Parse locations
	locFile, err := os.Open(filepath.Join(dir, "GeoLite2-Country-Locations-en.csv"))
	if err != nil {
		return nil, fmt.Errorf("opening locations file: %w", err)
	}
	defer locFile.Close()

	locations, err := ParseLocations(locFile)
	if err != nil {
		return nil, fmt.Errorf("parsing locations: %w", err)
	}

	result := NewCountryCIDRs()

	// Parse IPv4 blocks
	v4File, err := os.Open(filepath.Join(dir, "GeoLite2-Country-Blocks-IPv4.csv"))
	if err != nil {
		return nil, fmt.Errorf("opening IPv4 blocks file: %w", err)
	}
	defer v4File.Close()

	v4Blocks, err := ParseBlocks(v4File, locations, targetSet)
	if err != nil {
		return nil, fmt.Errorf("parsing IPv4 blocks: %w", err)
	}
	result.V4 = v4Blocks

	// Parse IPv6 blocks
	v6File, err := os.Open(filepath.Join(dir, "GeoLite2-Country-Blocks-IPv6.csv"))
	if err != nil {
		return nil, fmt.Errorf("opening IPv6 blocks file: %w", err)
	}
	defer v6File.Close()

	v6Blocks, err := ParseBlocks(v6File, locations, targetSet)
	if err != nil {
		return nil, fmt.Errorf("parsing IPv6 blocks: %w", err)
	}
	result.V6 = v6Blocks

	optimized, err := optimizeCountryCIDRs(result)
	if err != nil {
		return nil, err
	}
	if err := saveOptimizedToCache(dir, countries, optimized); err != nil {
		return nil, err
	}

	return optimized, nil
}

// Stats returns a summary of CIDR counts per country.
func (c *CountryCIDRs) Stats() map[string][2]int {
	stats := make(map[string][2]int)
	for country, prefixes := range c.V4 {
		s := stats[country]
		s[0] = len(prefixes)
		stats[country] = s
	}
	for country, prefixes := range c.V6 {
		s := stats[country]
		s[1] = len(prefixes)
		stats[country] = s
	}
	return stats
}
