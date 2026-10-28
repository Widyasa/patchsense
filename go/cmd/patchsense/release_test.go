package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestVersionMatchesCargoToml(t *testing.T) {
	cargo, err := os.ReadFile(filepath.Join("..", "..", "..", "Cargo.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cargo), `version = "`+patchsenseVersion+`"`) {
		t.Fatalf("go launcher version %s is not the workspace version", patchsenseVersion)
	}
}

func TestLaunchFakeAndRealBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake launcher is a shell script")
	}
	triple := "x86_64-unknown-linux-gnu"
	script := []byte("#!/bin/sh\nif [ \"${1:-}\" = \"--exit\" ]; then exit \"$2\"; fi\nif [ \"${1:-}\" = \"--version\" ]; then echo fake-patchsense 0.1.0; exit 0; fi\nprintf 'args:%s\\n' \"$*\"\nexit 0\n")
	srv, closeSrv := serveRelease(t, triple, script)
	t.Cleanup(closeSrv)
	t.Setenv("PATCHSENSE_RELEASE_BASE", srv.URL+"/releases/download")
	t.Setenv("PATCHSENSE_TARGET", triple)
	cache := t.TempDir()
	t.Setenv("PATCHSENSE_CACHE_DIR", cache)

	out, code := launchCapture(t, "--version")
	if code != 0 || out != "fake-patchsense 0.1.0\n" {
		t.Fatalf("version code=%d out=%q", code, out)
	}
	out, code = launchCapture(t, "hello", "two words")
	if code != 0 || out != "args:hello two words\n" {
		t.Fatalf("args code=%d out=%q", code, out)
	}
	_, code = launchCapture(t, "--exit", "3")
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}

	closeSrv()
	out, code = launchCapture(t, "--version")
	if code != 0 || out != "fake-patchsense 0.1.0\n" {
		t.Fatalf("offline cache code=%d out=%q", code, out)
	}

	t.Setenv("PATCHSENSE_CACHE_DIR", t.TempDir())
	_, code = launchCapture(t, "--version")
	if code == 0 {
		t.Fatal("uncached run succeeded without a server")
	}
}

func TestRealReleaseBinaryVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("host binary is a linux executable")
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "target", "release", "patchsense"))
	if err != nil {
		t.Skip(err)
	}
	triple := "x86_64-unknown-linux-gnu"
	srv, closeSrv := serveRelease(t, triple, body)
	t.Cleanup(closeSrv)
	t.Setenv("PATCHSENSE_RELEASE_BASE", srv.URL+"/releases/download")
	t.Setenv("PATCHSENSE_TARGET", triple)
	t.Setenv("PATCHSENSE_CACHE_DIR", t.TempDir())
	out, code := launchCapture(t, "--version")
	if code != 0 || out != "patchsense 0.1.0\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestChecksumMismatchIsNotCached(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake launcher is a shell script")
	}
	triple := "x86_64-unknown-linux-gnu"
	archive := tarGz(t, "patchsense", []byte("#!/bin/sh\necho nope\n"))
	sum := sha256.Sum256(archive)
	manifest := map[string]any{
		"artifacts": map[string]any{
			"patchsense-" + triple + ".tar.gz": map[string]any{
				"name":           "patchsense-" + triple + ".tar.gz",
				"kind":           "executable-zip",
				"target_triples": []string{triple},
				"checksums":      map[string]string{"sha256": hex.EncodeToString(sum[:])},
			},
		},
	}
	raw, _ := json.Marshal(manifest)
	var edited map[string]any
	if err := json.Unmarshal(raw, &edited); err != nil {
		t.Fatal(err)
	}
	arts := edited["artifacts"].(map[string]any)
	entry := arts["patchsense-"+triple+".tar.gz"].(map[string]any)
	entry["checksums"] = map[string]string{"sha256": strings.Repeat("ab", 32)}

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/download/v0.1.0/dist-manifest.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(edited)
	})
	mux.HandleFunc("/releases/download/v0.1.0/patchsense-"+triple+".tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("PATCHSENSE_RELEASE_BASE", srv.URL+"/releases/download")
	t.Setenv("PATCHSENSE_TARGET", triple)
	cache := t.TempDir()
	t.Setenv("PATCHSENSE_CACHE_DIR", cache)
	_, err := launch([]string{"--version"})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err=%v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(cache, "bin", patchsenseVersion, triple, "patchsense"))
	if len(matches) != 0 {
		t.Fatalf("cached bad binary: %v", matches)
	}
}

func TestGoInstallRunsReleaseBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake launcher is a shell script")
	}
	if os.Getenv("PATCHSENSE_SKIP_INSTALL") == "1" {
		t.Skip()
	}
	triple := "x86_64-unknown-linux-gnu"
	script := []byte("#!/bin/sh\necho installed-patchsense\n")
	srv, closeSrv := serveRelease(t, triple, script)
	defer closeSrv()
	gobin := t.TempDir()
	cmd := exec.Command("go", "install", ".")
	cmd.Env = append(os.Environ(), "GOBIN="+gobin)
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go install: %v\n%s", err, out)
	}
	run := exec.Command(filepath.Join(gobin, "patchsense"))
	run.Env = append(os.Environ(),
		"PATCHSENSE_RELEASE_BASE="+srv.URL+"/releases/download",
		"PATCHSENSE_TARGET="+triple,
		"PATCHSENSE_CACHE_DIR="+t.TempDir(),
	)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("installed launcher: %v\n%s", err, out)
	}
	if string(out) != "installed-patchsense\n" {
		t.Fatalf("out=%q", out)
	}
}

func launchCapture(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	code, launchErr := launch(args)
	w.Close()
	os.Stdout = old
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	r.Close()
	if launchErr != nil && code == 0 {
		return launchErr.Error(), 1
	}
	return buf.String(), code
}

func serveRelease(t *testing.T, triple string, binary []byte) (*httptest.Server, func()) {
	t.Helper()
	archive := tarGz(t, "patchsense", binary)
	sum := sha256.Sum256(archive)
	name := "patchsense-" + triple + ".tar.gz"
	manifest := map[string]any{
		"artifacts": map[string]any{
			name: map[string]any{
				"name":           name,
				"kind":           "executable-zip",
				"target_triples": []string{triple},
				"checksums":      map[string]string{"sha256": hex.EncodeToString(sum[:])},
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/download/v0.1.0/dist-manifest.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/releases/download/v0.1.0/"+name, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	var once sync.Once
	return srv, func() { once.Do(srv.Close) }
}

func tarGz(t *testing.T, exe string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	name := "patchsense-x86_64-unknown-linux-gnu/" + exe
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
