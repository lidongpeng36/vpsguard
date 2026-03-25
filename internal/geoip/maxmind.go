package geoip

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxmindDownloadURL = "https://download.maxmind.com/app/geoip_download"
	downloadTimeout    = 5 * time.Minute
)

// Downloader handles fetching and extracting MaxMind GeoIP databases.
type Downloader struct {
	LicenseKey string
	Edition    string
	DataDir    string
	HTTPClient *http.Client
}

// NewDownloader creates a Downloader with sensible defaults.
func NewDownloader(licenseKey, edition, dataDir string) *Downloader {
	return &Downloader{
		LicenseKey: licenseKey,
		Edition:    edition,
		DataDir:    dataDir,
		HTTPClient: &http.Client{Timeout: downloadTimeout},
	}
}

// DownloadURL returns the full download URL for the configured edition.
func (d *Downloader) DownloadURL() string {
	return fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=zip",
		maxmindDownloadURL, d.Edition, d.LicenseKey)
}

// Download fetches the latest GeoIP database and extracts CSV files to DataDir.
// Returns the path to the extracted directory containing the CSV files.
func (d *Downloader) Download() (string, error) {
	if err := os.MkdirAll(d.DataDir, 0755); err != nil {
		return "", fmt.Errorf("creating data dir: %w", err)
	}

	// Download to temp file
	zipPath := filepath.Join(d.DataDir, "download.zip")
	if err := d.downloadToFile(zipPath); err != nil {
		return "", fmt.Errorf("downloading: %w", err)
	}
	defer os.Remove(zipPath)

	// Extract
	extractDir, err := d.extractZip(zipPath)
	if err != nil {
		return "", fmt.Errorf("extracting: %w", err)
	}

	return extractDir, nil
}

// downloadToFile fetches the URL and saves to the given path.
func (d *Downloader) downloadToFile(path string) error {
	resp, err := d.HTTPClient.Get(d.DownloadURL())
	if err != nil {
		return fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// extractZip extracts CSV files from the zip archive.
// MaxMind zips contain a subdirectory like "GeoLite2-Country-CSV_20240101/".
// We extract the CSV files to DataDir/current/.
func (d *Downloader) extractZip(zipPath string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	// Extract to a temp dir first, then atomic rename
	tmpDir := filepath.Join(d.DataDir, "extracting")
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	csvCount := 0
	for _, f := range r.File {
		name := filepath.Base(f.Name)
		// Only extract CSV files we need
		if !strings.HasSuffix(name, ".csv") {
			continue
		}
		if err := extractFile(f, filepath.Join(tmpDir, name)); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("extracting %s: %w", name, err)
		}
		csvCount++
	}

	if csvCount == 0 {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("no CSV files found in zip archive")
	}

	// Atomic replace: remove old "current", rename "extracting" to "current"
	currentDir := filepath.Join(d.DataDir, "current")
	os.RemoveAll(currentDir)
	if err := os.Rename(tmpDir, currentDir); err != nil {
		return "", fmt.Errorf("renaming extracted dir: %w", err)
	}

	return currentDir, nil
}

// extractFile extracts a single file from the zip archive.
func extractFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Limit extraction size to 500MB to prevent zip bombs
	limited := io.LimitReader(rc, 500*1024*1024)
	if _, err := io.Copy(out, limited); err != nil {
		return err
	}
	return nil
}

// CurrentDataDir returns the path to the currently extracted CSV directory,
// or empty string if no data has been downloaded yet.
func (d *Downloader) CurrentDataDir() string {
	dir := filepath.Join(d.DataDir, "current")
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	return dir
}

// HasData returns true if extracted GeoIP data exists locally.
func (d *Downloader) HasData() bool {
	return d.CurrentDataDir() != ""
}
