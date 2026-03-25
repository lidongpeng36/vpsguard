// Package daemon implements the VPSGuard daemon lifecycle, including
// signal handling, graceful shutdown, and config hot-reload.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lidongpeng36/vpsguard/internal/config"
	"github.com/lidongpeng36/vpsguard/internal/updater"
)

// Daemon manages the VPSGuard service lifecycle.
type Daemon struct {
	configPath string
	cfg        *config.Config
	updater    *updater.Updater
	logger     *slog.Logger
	cancel     context.CancelFunc
}

// New creates a new Daemon from a config file path.
func New(configPath string) (*Daemon, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	logger := setupLogger(cfg)
	u := updater.New(cfg, logger)

	return &Daemon{
		configPath: configPath,
		cfg:        cfg,
		updater:    u,
		logger:     logger,
	}, nil
}

// NewFromConfig creates a Daemon from an already-parsed config (for testing).
func NewFromConfig(cfg *config.Config, configPath string) *Daemon {
	logger := setupLogger(cfg)
	u := updater.New(cfg, logger)
	return &Daemon{
		configPath: configPath,
		cfg:        cfg,
		updater:    u,
		logger:     logger,
	}
}

// Run starts the daemon: loads initial data, applies rules, then enters
// the main loop handling signals and periodic updates.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, d.cancel = context.WithCancel(ctx)

	d.logger.Info("vpsguard starting",
		"mode", d.cfg.Mode,
		"countries", d.cfg.Countries,
		"whitelist_count", len(d.cfg.Whitelist),
	)

	// Check prerequisites
	if err := d.checkPrerequisites(); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}

	// Initial load
	if err := d.updater.InitialLoad(ctx); err != nil {
		return fmt.Errorf("initial load failed: %w", err)
	}

	// Start periodic update in background
	go d.updater.RunSchedule(ctx)
	go d.updater.RunStatsSampler(ctx)

	// Enter signal loop
	d.signalLoop(ctx)

	// Cleanup on exit
	return d.shutdown()
}

// checkPrerequisites verifies the runtime environment.
func (d *Daemon) checkPrerequisites() error {
	// Check running as root (needed for nftables)
	if os.Geteuid() != 0 {
		return fmt.Errorf("vpsguard must run as root (need CAP_NET_ADMIN for nftables)")
	}

	return nil
}

// signalLoop blocks until the context is cancelled or a termination signal is received.
// SIGHUP triggers config reload, SIGUSR1 triggers immediate GeoIP update.
func (d *Daemon) signalLoop(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("context cancelled, shutting down")
			return
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				d.handleReload()
			case syscall.SIGUSR1:
				d.handleForceUpdate(ctx)
			case syscall.SIGTERM, syscall.SIGINT:
				d.logger.Info("received termination signal", "signal", sig)
				return
			}
		}
	}
}

// handleReload reloads the configuration file and reapplies rules.
func (d *Daemon) handleReload() {
	d.logger.Info("reloading configuration", "path", d.configPath)

	newCfg, err := config.Load(d.configPath)
	if err != nil {
		d.logger.Error("config reload failed, keeping current config", "error", err)
		return
	}

	if err := d.updater.Reload(newCfg); err != nil {
		d.logger.Error("rule reload failed", "error", err)
		return
	}

	d.cfg = newCfg
	d.logger.Info("configuration reloaded successfully",
		"mode", newCfg.Mode,
		"countries", newCfg.Countries,
	)
}

// handleForceUpdate triggers an immediate GeoIP data update.
func (d *Daemon) handleForceUpdate(ctx context.Context) {
	d.logger.Info("forced GeoIP update triggered (SIGUSR1)")
	if err := d.updater.UpdateNow(ctx); err != nil {
		d.logger.Error("forced update failed", "error", err)
	}
}

// shutdown performs graceful cleanup on daemon exit.
func (d *Daemon) shutdown() error {
	d.logger.Info("shutting down")
	var shutdownErr error

	if d.cfg.Daemon.CleanupOnStop {
		d.logger.Info("cleaning up nftables rules")
		if err := d.updater.Cleanup(); err != nil {
			d.logger.Error("cleanup failed", "error", err)
			shutdownErr = err
		} else {
			d.logger.Info("nftables rules cleaned up")
		}
	} else {
		d.logger.Info("keeping nftables rules (cleanup_on_stop=false)")
	}

	if err := d.updater.WriteStoppedStatus(shutdownErr); err != nil {
		d.logger.Warn("failed to persist stopped status", "error", err)
	}

	d.logger.Info("vpsguard stopped")
	return shutdownErr
}

// Stop cancels the daemon context, triggering shutdown.
func (d *Daemon) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
}

// Status returns the current daemon and updater status.
func (d *Daemon) Status() updater.Status {
	return d.updater.GetStatus()
}

// setupLogger creates a slog.Logger based on configuration.
func setupLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case config.LogDebug:
		level = slog.LevelDebug
	case config.LogWarn:
		level = slog.LevelWarn
	case config.LogError:
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// Fall back to stderr
			handler = slog.NewTextHandler(os.Stderr, opts)
			slog.New(handler).Error("failed to open log file, falling back to stderr",
				"file", cfg.Log.File, "error", err)
		} else {
			handler = slog.NewJSONHandler(f, opts)
		}
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}
