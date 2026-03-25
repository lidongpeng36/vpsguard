package geoip

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadURL(t *testing.T) {
	d := NewDownloader("test-key", "GeoLite2-Country-CSV", "/tmp/data")
	got := d.DownloadURL()
	want := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=test-key&suffix=zip"
	if got != want {
		t.Errorf("DownloadURL() = %q, want %q", got, want)
	}
}

func TestHasDataNoDir(t *testing.T) {
	d := NewDownloader("key", "edition", t.TempDir()+"/nonexistent")
	if d.HasData() {
		t.Error("HasData() = true for nonexistent dir")
	}
}

func TestHasDataWithDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "current"), 0755)

	d := NewDownloader("key", "edition", dir)
	if !d.HasData() {
		t.Error("HasData() = false when current/ exists")
	}
}

func TestCurrentDataDir(t *testing.T) {
	dir := t.TempDir()

	d := NewDownloader("key", "edition", dir)
	if got := d.CurrentDataDir(); got != "" {
		t.Errorf("CurrentDataDir() = %q, want empty", got)
	}

	currentDir := filepath.Join(dir, "current")
	os.MkdirAll(currentDir, 0755)
	if got := d.CurrentDataDir(); got != currentDir {
		t.Errorf("CurrentDataDir() = %q, want %q", got, currentDir)
	}
}

func TestDownloadAndExtract(t *testing.T) {
	// Create a test zip file in memory
	zipBuf := createTestZip(t)

	// Start test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query params
		q := r.URL.Query()
		if q.Get("license_key") != "test-key" {
			t.Errorf("license_key = %q, want test-key", q.Get("license_key"))
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipBuf)
	}))
	defer server.Close()

	dir := t.TempDir()
	d := &Downloader{
		LicenseKey: "test-key",
		Edition:    "GeoLite2-Country-CSV",
		DataDir:    dir,
		HTTPClient: server.Client(),
	}

	// Override the download URL to use test server
	// We need to use the downloadToFile directly since Download() uses the real URL
	zipPath := filepath.Join(dir, "test.zip")
	os.WriteFile(zipPath, zipBuf, 0644)

	extractDir, err := d.extractZip(zipPath)
	if err != nil {
		t.Fatalf("extractZip error: %v", err)
	}

	// Verify extracted files exist
	for _, name := range []string{
		"GeoLite2-Country-Locations-en.csv",
		"GeoLite2-Country-Blocks-IPv4.csv",
		"GeoLite2-Country-Blocks-IPv6.csv",
	} {
		path := filepath.Join(extractDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing extracted file %s: %v", name, err)
		}
	}

	// Verify current dir was set
	if !d.HasData() {
		t.Error("HasData() should be true after extraction")
	}
}

func TestExtractZipNoCSV(t *testing.T) {
	// Create a zip with no CSV files
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "empty.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	// Add a non-CSV file
	fw, _ := w.Create("readme.txt")
	fw.Write([]byte("hello"))
	w.Close()
	f.Close()

	d := NewDownloader("key", "edition", dir)
	_, err = d.extractZip(zipPath)
	if err == nil {
		t.Fatal("expected error for zip with no CSV files")
	}
}

func TestExtractZipAtomicReplace(t *testing.T) {
	dir := t.TempDir()

	// Create initial "current" dir with old file
	currentDir := filepath.Join(dir, "current")
	os.MkdirAll(currentDir, 0755)
	os.WriteFile(filepath.Join(currentDir, "old.csv"), []byte("old data"), 0644)

	// Extract new zip
	zipBuf := createTestZip(t)
	zipPath := filepath.Join(dir, "new.zip")
	os.WriteFile(zipPath, zipBuf, 0644)

	d := NewDownloader("key", "edition", dir)
	extractDir, err := d.extractZip(zipPath)
	if err != nil {
		t.Fatalf("extractZip error: %v", err)
	}

	// Old file should be gone
	if _, err := os.Stat(filepath.Join(extractDir, "old.csv")); err == nil {
		t.Error("old.csv should have been removed after atomic replace")
	}

	// New files should exist
	if _, err := os.Stat(filepath.Join(extractDir, "GeoLite2-Country-Locations-en.csv")); err != nil {
		t.Error("new CSV files should exist after extraction")
	}
}

// createTestZip builds a zip archive containing test MaxMind CSV files.
func createTestZip(t *testing.T) []byte {
	t.Helper()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)

	// Simulate MaxMind's zip structure: files in a subdirectory
	prefix := "GeoLite2-Country-CSV_20240101/"

	files := map[string]string{
		prefix + "GeoLite2-Country-Locations-en.csv": locationsCSV,
		prefix + "GeoLite2-Country-Blocks-IPv4.csv":  blocksV4CSV,
		prefix + "GeoLite2-Country-Blocks-IPv6.csv":  blocksV6CSV,
	}

	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	w.Close()
	f.Close()

	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
