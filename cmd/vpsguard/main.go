// VPSGuard - GeoIP-based VPS inbound traffic protection.
//
// Usage:
//
//	vpsguard [flags]
//
// Flags:
//
//	-config string    Path to config file (default "/etc/vpsguard/config.yaml")
//	-check            Validate config and exit
//	-dry-run          Generate ruleset and print to stdout, don't apply
//	-status           Show current status
//	-version          Print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/lidongpeng36/vpsguard/internal/config"
	"github.com/lidongpeng36/vpsguard/internal/daemon"
	"github.com/lidongpeng36/vpsguard/internal/firewall"
	"github.com/lidongpeng36/vpsguard/internal/geoip"
	"github.com/lidongpeng36/vpsguard/internal/updater"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "/etc/vpsguard/config.yaml", "Path to config file")
	check := flag.Bool("check", false, "Validate config and check prerequisites, then exit")
	dryRun := flag.Bool("dry-run", false, "Generate nftables ruleset and print to stdout")
	showVersion := flag.Bool("version", false, "Print version and exit")
	showStatus := flag.Bool("status", false, "Show current rule status")

	flag.Parse()

	if *showVersion {
		fmt.Printf("vpsguard %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	if *check {
		runCheck(*configPath)
		return
	}

	if *dryRun {
		runDryRun(*configPath)
		return
	}

	if *showStatus {
		runStatus()
		return
	}

	// Normal daemon mode
	runDaemon(*configPath)
}

// runCheck validates the config and checks prerequisites.
func runCheck(configPath string) {
	fmt.Printf("Checking config: %s\n", configPath)

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Mode:       %s\n", cfg.Mode)
	fmt.Printf("  Countries:  %v\n", cfg.Countries)
	fmt.Printf("  Whitelist:  %d entries\n", len(cfg.Whitelist))
	fmt.Printf("  GeoIP dir:  %s\n", cfg.GeoIP.DataDir)
	fmt.Printf("  Update:     %s\n", cfg.GeoIP.UpdateInterval)
	fmt.Printf("  Table:      %s (priority %d)\n", cfg.NFTables.TableName, cfg.NFTables.Priority)
	fmt.Printf("  Log level:  %s\n", cfg.Log.Level)
	fmt.Printf("  Cleanup:    %v\n", cfg.Daemon.CleanupOnStop)

	// Check whitelist parsing
	prefixes, err := cfg.ParsedWhitelist()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: whitelist parsing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Whitelist (parsed): %d prefixes\n", len(prefixes))

	fmt.Println("\nConfig OK")
}

// runDryRun generates the nftables ruleset without applying it.
func runDryRun(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	dl := geoip.NewDownloader(cfg.GeoIP.LicenseKey, cfg.GeoIP.Edition, cfg.GeoIP.DataDir)
	if !dl.HasData() {
		fmt.Fprintf(os.Stderr, "ERROR: no GeoIP data found in %s\n", cfg.GeoIP.DataDir)
		fmt.Fprintf(os.Stderr, "Run the daemon first to download data, or manually download.\n")
		os.Exit(1)
	}

	cidrs, err := geoip.LoadFromDir(dl.CurrentDataDir(), cfg.Countries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: loading GeoIP data: %v\n", err)
		os.Exit(1)
	}

	// Print stats
	stats := cidrs.Stats()
	fmt.Fprintf(os.Stderr, "# GeoIP data loaded:\n")
	for country, counts := range stats {
		fmt.Fprintf(os.Stderr, "#   %s: %d IPv4, %d IPv6 CIDRs\n", country, counts[0], counts[1])
	}
	fmt.Fprintf(os.Stderr, "#\n")

	u := updater.New(cfg, nil)
	params, err := u.BuildParamsFromData(cidrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: building params: %v\n", err)
		os.Exit(1)
	}

	fw := firewall.NewManager(cfg.NFTables.TableName, cfg.NFTables.Priority)
	ruleset := fw.GenerateRuleset(params)
	fmt.Print(ruleset)
}

// runStatus shows current nftables table status.
func runStatus() {
	fmt.Println("VPSGuard Status")
	fmt.Println("===============")

	// Try to list the table
	fw := firewall.NewManager("vpsguard", 0)
	if err := fw.Verify(); err != nil {
		fmt.Printf("Table status: NOT ACTIVE (%v)\n", err)
	} else {
		fmt.Println("Table status: ACTIVE")
	}
}

// runDaemon starts the main daemon process.
func runDaemon(configPath string) {
	d, err := daemon.New(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}
