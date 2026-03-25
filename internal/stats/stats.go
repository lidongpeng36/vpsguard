package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultRetention = 8 * 24 * time.Hour
)

// CounterSource provides current cumulative drop counters.
type CounterSource interface {
	DropCounters() (map[string]uint64, error)
}

// ServiceStatus is the persisted daemon status snapshot.
type ServiceStatus struct {
	Active         bool      `json:"active"`
	Mode           string    `json:"mode"`
	Countries      []string  `json:"countries"`
	TableName      string    `json:"table_name"`
	WhitelistCount int       `json:"whitelist_count"`
	LastUpdate     time.Time `json:"last_update"`
	LastSample     time.Time `json:"last_sample"`
	LastError      string    `json:"last_error"`
}

// Sample is a point-in-time delta snapshot.
type Sample struct {
	Timestamp time.Time         `json:"timestamp"`
	Counters  map[string]uint64 `json:"counters"`
}

// State is the persisted rolling stats state.
type State struct {
	LastUpdated time.Time         `json:"last_updated"`
	LastTotals  map[string]uint64 `json:"last_totals"`
	Samples     []Sample          `json:"samples"`
	Status      ServiceStatus     `json:"status"`
}

// WindowReport contains drop counts for a time window.
type WindowReport struct {
	Window   time.Duration
	Counters map[string]uint64
}

// Report is the user-facing summary.
type Report struct {
	GeneratedAt time.Time
	Windows     []WindowReport
}

// Collector persists rolling drop statistics.
type Collector struct {
	path      string
	source    CounterSource
	now       func() time.Time
	retention time.Duration
}

// New creates a stats collector.
func New(path string, source CounterSource) *Collector {
	return &Collector{
		path:      path,
		source:    source,
		now:       time.Now,
		retention: defaultRetention,
	}
}

// Sample reads current counters and persists a delta snapshot.
func (c *Collector) Sample() error {
	current, err := c.source.DropCounters()
	if err != nil {
		return err
	}

	state, err := c.load()
	if err != nil {
		return err
	}

	now := c.now()
	if len(state.LastTotals) == 0 {
		state.LastTotals = cloneCounters(current)
		state.LastUpdated = now
		state.Status.LastSample = now
		return c.save(state)
	}

	delta := diffCounters(current, state.LastTotals)
	state.Samples = append(state.Samples, Sample{
		Timestamp: now,
		Counters:  delta,
	})
	state.Samples = trimSamples(state.Samples, now.Add(-c.retention))
	state.LastTotals = cloneCounters(current)
	state.LastUpdated = now
	state.Status.LastSample = now
	return c.save(state)
}

// Report builds a 1h/24h/7d report using persisted samples plus current live counters.
func (c *Collector) Report() (*Report, error) {
	current, err := c.source.DropCounters()
	if err != nil {
		return nil, err
	}

	state, err := c.load()
	if err != nil {
		return nil, err
	}

	now := c.now()
	samples := append([]Sample(nil), state.Samples...)
	if len(state.LastTotals) > 0 {
		samples = append(samples, Sample{
			Timestamp: now,
			Counters:  diffCounters(current, state.LastTotals),
		})
	}

	windows := []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}
	report := &Report{
		GeneratedAt: now,
		Windows:     make([]WindowReport, 0, len(windows)),
	}
	for _, window := range windows {
		report.Windows = append(report.Windows, WindowReport{
			Window:   window,
			Counters: sumWindow(samples, now.Add(-window)),
		})
	}
	return report, nil
}

// Load reads the persisted stats snapshot from disk.
func Load(path string) (*State, error) {
	return (&Collector{path: path}).load()
}

// ReportFromState builds a report from persisted samples only.
func ReportFromState(state *State) *Report {
	windows := []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}
	report := &Report{
		GeneratedAt: state.LastUpdated,
		Windows:     make([]WindowReport, 0, len(windows)),
	}
	for _, window := range windows {
		report.Windows = append(report.Windows, WindowReport{
			Window:   window,
			Counters: sumWindow(state.Samples, state.LastUpdated.Add(-window)),
		})
	}
	return report
}

// UpdateStatus writes service metadata into the persisted snapshot.
func (c *Collector) UpdateStatus(status ServiceStatus) error {
	state, err := c.load()
	if err != nil {
		return err
	}
	if status.LastSample.IsZero() {
		status.LastSample = state.Status.LastSample
	}
	state.Status = status
	return c.save(state)
}

func (c *Collector) load() (*State, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{
				LastTotals: make(map[string]uint64),
			}, nil
		}
		return nil, fmt.Errorf("reading stats state: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing stats state: %w", err)
	}
	if state.LastTotals == nil {
		state.LastTotals = make(map[string]uint64)
	}
	return &state, nil
}

func (c *Collector) save(state *State) error {
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating stats dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding stats state: %w", err)
	}

	tmpPath := c.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing stats temp file: %w", err)
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		return fmt.Errorf("renaming stats file: %w", err)
	}
	return nil
}

func diffCounters(current, previous map[string]uint64) map[string]uint64 {
	delta := make(map[string]uint64)
	for country, currentValue := range current {
		prev := previous[country]
		if currentValue >= prev {
			delta[country] = currentValue - prev
		} else {
			// Counter reset after ruleset recreation.
			delta[country] = currentValue
		}
	}
	return delta
}

func sumWindow(samples []Sample, since time.Time) map[string]uint64 {
	result := make(map[string]uint64)
	for _, sample := range samples {
		if sample.Timestamp.Before(since) {
			continue
		}
		for country, count := range sample.Counters {
			result[country] += count
		}
	}
	return result
}

func trimSamples(samples []Sample, since time.Time) []Sample {
	idx := 0
	for idx < len(samples) && samples[idx].Timestamp.Before(since) {
		idx++
	}
	if idx == 0 {
		return samples
	}
	return append([]Sample(nil), samples[idx:]...)
}

func cloneCounters(src map[string]uint64) map[string]uint64 {
	dst := make(map[string]uint64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
