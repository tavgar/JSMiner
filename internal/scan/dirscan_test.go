package scan

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestScanDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "scandir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// regular JS file
	os.WriteFile(filepath.Join(dir, "a.js"), []byte("test@test.com"), 0644)
	// wasm file
	os.WriteFile(filepath.Join(dir, "b.wasm"), []byte("1.2.3.4"), 0644)

	// zip archive
	zipPath := filepath.Join(dir, "c.zip")
	createZip(zipPath, "c.js", "5.6.7.8")

	// jar archive
	jarPath := filepath.Join(dir, "d.jar")
	createZip(jarPath, "d.js", "9.8.7.6")

	e := NewExtractor(false, false)
	matches, err := e.ScanDir(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 4 {
		t.Fatalf("expected 4 matches, got %d", len(matches))
	}
}

func createZip(path, name, content string) {
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	w, _ := zw.Create(name)
	w.Write([]byte(content))
	zw.Close()
	f.Close()
}
