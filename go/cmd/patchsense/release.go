package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultReleaseBase = "https://github.com/Widyasa/patchsense/releases/download"

type artifact struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	TargetTriples []string `json:"target_triples"`
	Checksums     struct {
		SHA256 string `json:"sha256"`
	} `json:"checksums"`
}

func detectTarget() (triple string, exe string, err error) {
	if override := os.Getenv("PATCHSENSE_TARGET"); override != "" {
		triple = override
	} else {
		cpu := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
		if cpu == "" {
			return "", "", fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
		}
		switch runtime.GOOS {
		case "linux":
			libc := "gnu"
			if isMusl() {
				libc = "musl"
			}
			triple = cpu + "-unknown-linux-" + libc
		case "darwin":
			triple = cpu + "-apple-darwin"
		case "windows":
			triple = cpu + "-pc-windows-msvc"
		default:
			return "", "", fmt.Errorf("unsupported operating system %s", runtime.GOOS)
		}
	}
	exe = "patchsense"
	if strings.Contains(triple, "windows") {
		exe = "patchsense.exe"
	}
	return triple, exe, nil
}

func isMusl() bool {
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		return true
	}
	out, _ := exec.Command("ldd", "--version").CombinedOutput()
	return strings.Contains(strings.ToLower(string(out)), "musl")
}

func cachePath(triple, exe string) (string, error) {
	root := os.Getenv("PATCHSENSE_CACHE_DIR")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("HOME is not set; set PATCHSENSE_CACHE_DIR")
		}
		root = filepath.Join(home, ".cache", "patchsense")
	}
	return filepath.Join(root, "bin", patchsenseVersion, triple, exe), nil
}

func releaseBase() string {
	base := os.Getenv("PATCHSENSE_RELEASE_BASE")
	if base == "" {
		base = defaultReleaseBase
	}
	return strings.TrimRight(base, "/")
}

func installBinary(triple, exe, cache string) error {
	prefix := releaseBase() + "/v" + patchsenseVersion
	body, err := httpGet(prefix + "/dist-manifest.json")
	if err != nil {
		return err
	}
	name, expected, err := selectArtifact(body, triple)
	if err != nil {
		return err
	}
	archive, err := os.CreateTemp("", "patchsense-*.tar.gz")
	if err != nil {
		return err
	}
	archiveName := archive.Name()
	defer os.Remove(archiveName)
	if err := httpDownload(prefix+"/"+name, archive); err != nil {
		archive.Close()
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	ok, err := checksumOK(archiveName, expected)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	extract, err := os.MkdirTemp("", "patchsense-extract-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(extract)
	if err := extractBinary(archiveName, extract, exe); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(cache), "."+exe+".partial")
	if err := copyFile(filepath.Join(extract, exe), staged); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, cache); err != nil {
		os.Remove(staged)
		return err
	}
	return nil
}

func selectArtifact(data []byte, triple string) (string, string, error) {
	for _, art := range artifactObjects(data) {
		if art.Kind != "executable-zip" {
			continue
		}
		matched := false
		for _, candidate := range art.TargetTriples {
			if candidate == triple {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		name := art.Name
		sha := strings.ToLower(strings.TrimSpace(art.Checksums.SHA256))
		if name == "" || sha == "" {
			return "", "", fmt.Errorf("release manifest entry for %s has no sha256", triple)
		}
		return name, sha, nil
	}
	return "", "", fmt.Errorf("no executable-zip for %s in the v%s release", triple, patchsenseVersion)
}

func artifactObjects(data []byte) []artifact {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	var found []artifact
	found = append(found, decodeArtifacts(root["artifacts"])...)
	var releases []struct {
		Artifacts json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(root["releases"], &releases); err == nil {
		for _, release := range releases {
			found = append(found, decodeArtifacts(release.Artifacts)...)
		}
	}
	return found
}

func decodeArtifacts(raw json.RawMessage) []artifact {
	if len(raw) == 0 {
		return nil
	}
	var asMap map[string]artifact
	if err := json.Unmarshal(raw, &asMap); err == nil && len(asMap) > 0 {
		out := make([]artifact, 0, len(asMap))
		for key, art := range asMap {
			if art.Name == "" {
				art.Name = key
			}
			if art.Kind == "" && len(art.TargetTriples) == 0 {
				continue
			}
			out = append(out, art)
		}
		if len(out) > 0 {
			return out
		}
	}
	var asList []artifact
	if err := json.Unmarshal(raw, &asList); err == nil {
		return asList
	}
	return nil
}

func extractBinary(archivePath, dest, exe string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("could not extract the release archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("could not extract the release archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		cleaned := path.Clean(hdr.Name)
		baseMatch := path.Base(cleaned) == exe && strings.Count(cleaned, "/") == 1
		if cleaned == exe || baseMatch {
			out, err := os.OpenFile(filepath.Join(dest, exe), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("archive does not contain %s", exe)
}

func execBinary(binary string, args []string) (int, error) {
	cmd := exec.Command(binary, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 0, fmt.Errorf("failed to execute %s: %w", binary, err)
}

func httpGet(url string) ([]byte, error) {
	resp, err := httpClient().Get(url)
	if err != nil {
		return nil, fmt.Errorf("download failed for %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("download failed for %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download failed for %s: %w", url, err)
	}
	return body, nil
}

func httpDownload(url string, dest *os.File) error {
	resp, err := httpClient().Get(url)
	if err != nil {
		return fmt.Errorf("download failed for %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("download failed for %s: HTTP %d", url, resp.StatusCode)
	}
	if _, err := io.Copy(dest, resp.Body); err != nil {
		return fmt.Errorf("download failed for %s: %w", url, err)
	}
	return nil
}

func httpClient() *http.Client {
	return &http.Client{
		Timeout: 180 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

func checksumOK(path, expected string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return false, err
	}
	actual := hex.EncodeToString(sum.Sum(nil))
	return actual == strings.ToLower(strings.TrimSpace(expected)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
