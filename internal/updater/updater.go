// Package updater orchestrates GeoIP data updates and nftables rule refreshes.
package updater

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/lidongpeng36/vpsguard/internal/config"
	"github.com/lidongpeng36/vpsguard/internal/firewall"
	"github.com/lidongpeng36/vpsguard/internal/geoip"
	"github.com/lidongpeng36/vpsguard/internal/stats"
)

// Updater manages the periodic GeoIP update cycle.
type Updater struct {
	cfg            *config.Config
	dl             *geoip.Downloader
	fw             *firewall.Manager
	statsCollector *stats.Collector
	logger         *slog.Logger

	mu         sync.Mutex
	lastUpdate time.Time
	lastErr    error
	cidrs      *geoip.CountryCIDRs
}

// New creates an Updater from the given configuration.
func New(cfg *config.Config, logger *slog.Logger) *Updater {
	dl := geoip.NewDownloader(cfg.GeoIP.LicenseKey, cfg.GeoIP.Edition, cfg.GeoIP.DataDir)
	fw := firewall.NewManager(cfg.NFTables.TableName, cfg.NFTables.Priority)

	u := &Updater{
		cfg:    cfg,
		dl:     dl,
		fw:     fw,
		logger: logger,
	}
	u.statsCollector = stats.New(cfg.StatsPath(), u)
	return u
}

// NewWithDeps creates an Updater with explicit dependencies (for testing).
func NewWithDeps(cfg *config.Config, dl *geoip.Downloader, fw *firewall.Manager, logger *slog.Logger) *Updater {
	u := &Updater{
		cfg:    cfg,
		dl:     dl,
		fw:     fw,
		logger: logger,
	}
	u.statsCollector = stats.New(cfg.StatsPath(), u)
	return u
}

// Status returns the current updater status.
type Status struct {
	LastUpdate time.Time
	LastError  error
	HasData    bool
	Stats      map[string][2]int // country → [v4_count, v6_count]
}

// Status returns the current status.
func (u *Updater) GetStatus() Status {
	u.mu.Lock()
	defer u.mu.Unlock()

	s := Status{
		LastUpdate: u.lastUpdate,
		LastError:  u.lastErr,
		HasData:    u.cidrs != nil,
	}
	if u.cidrs != nil {
		s.Stats = u.cidrs.Stats()
	}
	return s
}

// InitialLoad loads GeoIP data (from cache or download) and applies firewall rules.
// This should be called once at startup.
func (u *Updater) InitialLoad(ctx context.Context) error {
	u.logger.Info("performing initial GeoIP data load")

	// Try existing cached data first
	if u.dl.HasData() {
		u.logger.Info("found cached GeoIP data, loading")
		if err := u.loadAndApply(u.dl.CurrentDataDir()); err != nil {
			u.logger.Warn("cached data load failed, will download fresh", "error", err)
		} else {
			u.logger.Info("loaded cached GeoIP data successfully")
			return nil
		}
	}

	// Download fresh data
	return u.UpdateNow(ctx)
}

// UpdateNow triggers an immediate GeoIP data update.
func (u *Updater) UpdateNow(ctx context.Context) error {
	u.logger.Info("downloading GeoIP data")

	dataDir, err := u.dl.Download()
	if err != nil {
		u.mu.Lock()
		u.lastErr = err
		u.mu.Unlock()
		if writeErr := u.writeStatus(true, err.Error()); writeErr != nil {
			u.logger.Warn("status snapshot update failed", "error", writeErr)
		}
		return fmt.Errorf("downloading GeoIP data: %w", err)
	}

	u.logger.Info("GeoIP data downloaded", "dir", dataDir)
	return u.loadAndApply(dataDir)
}

// loadAndApply parses GeoIP data from the given directory and applies firewall rules.
func (u *Updater) loadAndApply(dataDir string) error {
	cidrs, err := geoip.LoadFromDir(dataDir, u.cfg.Countries)
	if err != nil {
		return fmt.Errorf("loading GeoIP data: %w", err)
	}

	// Log stats
	stats := cidrs.Stats()
	for country, counts := range stats {
		u.logger.Info("loaded country CIDRs",
			"country", country,
			"ipv4", counts[0],
			"ipv6", counts[1],
		)
	}

	// Sanity check: make sure we have some data
	totalV4, totalV6 := 0, 0
	for _, counts := range stats {
		totalV4 += counts[0]
		totalV6 += counts[1]
	}
	if totalV4 == 0 && totalV6 == 0 {
		return fmt.Errorf("no CIDR data found for configured countries: %v", u.cfg.Countries)
	}

	// Build firewall params
	params, err := u.buildParams(cidrs)
	if err != nil {
		return fmt.Errorf("building firewall params: %w", err)
	}

	// Apply ruleset in two phases (structure + batched elements)
	u.logger.Info("applying nftables ruleset",
		"mode", u.cfg.Mode,
		"v4_prefixes", totalV4,
		"v6_prefixes", totalV6,
	)

	if err := u.fw.Apply(params); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}

	// Verify
	if err := u.fw.Verify(); err != nil {
		u.logger.Warn("ruleset verification warning", "error", err)
	}

	// Update state
	u.mu.Lock()
	u.lastUpdate = time.Now()
	u.lastErr = nil
	u.cidrs = cidrs
	u.mu.Unlock()

	if err := u.writeStatus(true, ""); err != nil {
		u.logger.Warn("status snapshot update failed", "error", err)
	}

	u.logger.Info("firewall rules applied successfully")
	return nil
}

// buildParams converts the loaded CIDRs and config whitelist into RulesetParams.
func (u *Updater) buildParams(cidrs *geoip.CountryCIDRs) (*firewall.RulesetParams, error) {
	whitelist, err := u.cfg.ParsedWhitelist()
	if err != nil {
		return nil, fmt.Errorf("parsing whitelist: %w", err)
	}

	var wlV4, wlV6 []netip.Prefix
	for _, p := range whitelist {
		if p.Addr().Is4() {
			wlV4 = append(wlV4, p)
		} else {
			wlV6 = append(wlV6, p)
		}
	}

	// Collect all geo CIDRs across countries
	var geoV4, geoV6 []netip.Prefix
	for _, prefixes := range cidrs.V4 {
		geoV4 = append(geoV4, prefixes...)
	}
	for _, prefixes := range cidrs.V6 {
		geoV6 = append(geoV6, prefixes...)
	}

	return &firewall.RulesetParams{
		Mode:        string(u.cfg.Mode),
		WhitelistV4: wlV4,
		WhitelistV6: wlV6,
		GeoV4:       geoV4,
		GeoV6:       geoV6,
	}, nil
}

// RunSchedule starts the periodic update loop. Blocks until ctx is cancelled.
func (u *Updater) RunSchedule(ctx context.Context) {
	interval := u.cfg.UpdateIntervalDuration()
	if interval <= 0 {
		interval = 48 * time.Hour
	}

	u.logger.Info("starting update scheduler", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			u.logger.Info("update scheduler stopped")
			return
		case <-ticker.C:
			u.logger.Info("scheduled GeoIP update starting")
			if err := u.UpdateNow(ctx); err != nil {
				u.logger.Error("scheduled update failed", "error", err)
			}
		}
	}
}

// Cleanup removes VPSGuard nftables rules.
func (u *Updater) Cleanup() error {
	return u.fw.Cleanup()
}

// DropCounters returns current cumulative drop counters from the firewall.
func (u *Updater) DropCounters() (map[string]uint64, error) {
	return u.fw.DropCounters()
}

// Reload reloads config and reapplies rules with existing GeoIP data.
func (u *Updater) Reload(cfg *config.Config) error {
	u.mu.Lock()
	oldCIDRs := u.cidrs
	u.mu.Unlock()

	u.cfg = cfg
	u.fw = firewall.NewManager(cfg.NFTables.TableName, cfg.NFTables.Priority)
	u.statsCollector = stats.New(cfg.StatsPath(), u)

	if oldCIDRs != nil {
		return u.loadAndApply(u.dl.CurrentDataDir())
	}
	if err := u.writeStatus(true, ""); err != nil {
		return err
	}
	return nil
}

// FirewallManager returns the underlying firewall manager (for dry-run support).
func (u *Updater) FirewallManager() *firewall.Manager {
	return u.fw
}

// StatsReport returns rolling drop statistics.
func (u *Updater) StatsReport() (*stats.Report, error) {
	return u.statsCollector.Report()
}

// SampleStats persists a current stats sample.
func (u *Updater) SampleStats() error {
	return u.statsCollector.Sample()
}

// WriteStoppedStatus marks the persisted status as inactive.
func (u *Updater) WriteStoppedStatus(lastErr error) error {
	msg := ""
	if lastErr != nil {
		msg = lastErr.Error()
	}
	return u.writeStatus(false, msg)
}

// BuildParamsFromData builds RulesetParams from existing data (for dry-run support).
func (u *Updater) BuildParamsFromData(cidrs *geoip.CountryCIDRs) (*firewall.RulesetParams, error) {
	return u.buildParams(cidrs)
}

// RunStatsSampler periodically snapshots nftables counters for rolling reports.
func (u *Updater) RunStatsSampler(ctx context.Context) {
	const interval = 5 * time.Minute

	if err := u.SampleStats(); err != nil {
		u.logger.Warn("initial stats sample failed", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.SampleStats(); err != nil {
				u.logger.Warn("stats sample failed", "error", err)
			} else if err := u.writeStatus(true, ""); err != nil {
				u.logger.Warn("status snapshot update failed", "error", err)
			}
		}
	}
}

func (u *Updater) writeStatus(active bool, lastErr string) error {
	u.mu.Lock()
	lastUpdate := u.lastUpdate
	u.mu.Unlock()

	return u.statsCollector.UpdateStatus(stats.ServiceStatus{
		Active:         active,
		Mode:           string(u.cfg.Mode),
		Countries:      append([]string(nil), u.cfg.Countries...),
		TableName:      u.cfg.NFTables.TableName,
		WhitelistCount: len(u.cfg.Whitelist),
		LastUpdate:     lastUpdate,
		LastError:      lastErr,
	})
}
