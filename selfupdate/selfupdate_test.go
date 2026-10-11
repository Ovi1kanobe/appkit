package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub serves one release on api.github.com and its files on a separate
// download host, as GitHub does, so the test sees where the token travels.
type fakeGitHub struct {
	server    *httptest.Server
	mu        sync.Mutex
	files     map[string][]byte
	checksums string
	version   string
	apiAuth   []string // Authorization values seen by the API host
	cdnAuth   []string // Authorization values seen by the download host
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{files: map[string][]byte{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Host {
		case "api.github.com":
			f.apiAuth = append(f.apiAuth, r.Header.Get("Authorization"))
			switch {
			case r.URL.Path == "/repos/owner/app/releases/latest":
				assets := []map[string]string{}
				for name := range f.files {
					assets = append(assets, map[string]string{"name": name, "url": "https://api.github.com/assets/" + name})
				}
				json.NewEncoder(w).Encode(map[string]any{"tag_name": "v" + f.version, "assets": assets})
			case strings.HasPrefix(r.URL.Path, "/assets/"):
				http.Redirect(w, r, "https://objects.example/"+strings.TrimPrefix(r.URL.Path, "/assets/"), http.StatusFound)
			default:
				http.NotFound(w, r)
			}
		case "objects.example":
			f.cdnAuth = append(f.cdnAuth, r.Header.Get("Authorization"))
			name := strings.TrimPrefix(r.URL.Path, "/")
			if name == "checksums.txt" {
				fmt.Fprint(w, f.checksums)
				return
			}
			if file, ok := f.files[name]; ok {
				w.Write(file)
				return
			}
			http.NotFound(w, r)
		default:
			http.Error(w, "unexpected host "+r.Host, 421)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

// publish sets the release to version with a script asset that prints reports.
func (f *fakeGitHub) publish(version, reports, checksumOf string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = version
	name := "app-" + runtime.GOOS + "-" + runtime.GOARCH
	script := []byte("#!/bin/sh\necho " + reports + "\n")
	f.files = map[string][]byte{name: script, "checksums.txt": nil}
	sum := sha256.Sum256(script)
	if checksumOf != "" {
		sum = sha256.Sum256([]byte(checksumOf))
	}
	f.checksums = hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

// client routes every host to the fake server while keeping the request's
// host and scheme as the updater saw them.
func (f *fakeGitHub) client() *http.Client {
	target, _ := url.Parse(f.server.URL)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.Host = r.URL.Host
		clone.URL.Scheme = target.Scheme
		clone.URL.Host = target.Host
		return http.DefaultTransport.RoundTrip(clone)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpdate(t *testing.T) {
	github := newFakeGitHub(t)
	updater := Updater{Repository: "owner/app", Name: "app", Token: "secret-token", Client: github.client()}
	dir := t.TempDir()
	real := filepath.Join(dir, "app-real")
	link := filepath.Join(dir, "app")
	old := []byte("#!/bin/sh\necho old\n")
	if err := os.WriteFile(real, old, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	unchanged := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("update succeeded")
		}
		if current, _ := os.ReadFile(real); string(current) != string(old) {
			t.Fatal("executable changed after a failed update")
		}
		if leftovers, _ := filepath.Glob(filepath.Join(dir, ".app*update-*")); len(leftovers) != 0 {
			t.Fatalf("staged files left behind: %v", leftovers)
		}
	}

	github.publish("1.2.3", "1.2.3", "something else")
	_, err := updater.Update(context.Background(), link)
	unchanged(t, err)
	if !strings.Contains(err.Error(), "checksums.txt") {
		t.Fatalf("bad checksum error: %v", err)
	}

	github.publish("1.2.3", "9.9.9", "")
	_, err = updater.Update(context.Background(), link)
	unchanged(t, err)
	if !strings.Contains(err.Error(), "9.9.9") {
		t.Fatalf("wrong version error: %v", err)
	}

	github.publish("1.2.3", "1.2.3", "")
	release, err := updater.Check(context.Background())
	if err != nil || release.Version != "1.2.3" || !release.Newer {
		t.Fatalf("check: %+v %v", release, err)
	}
	installed, err := updater.Update(context.Background(), link)
	if err != nil || installed != "1.2.3" {
		t.Fatalf("update: %q %v", installed, err)
	}
	current, err := os.ReadFile(real)
	if err != nil || !strings.Contains(string(current), "echo 1.2.3") {
		t.Fatalf("executable not replaced: %q %v", current, err)
	}
	if info, _ := os.Stat(real); info.Mode().Perm() != 0o750 {
		t.Fatalf("permissions changed to %v", info.Mode().Perm())
	}
	if target, _ := os.Readlink(link); target != real {
		t.Fatal("symlink was replaced instead of its target")
	}

	github.mu.Lock()
	defer github.mu.Unlock()
	for _, auth := range github.apiAuth {
		if auth != "Bearer secret-token" {
			t.Fatal("API request without the token")
		}
	}
	for _, auth := range github.cdnAuth {
		if auth != "" {
			t.Fatal("token sent to the download host")
		}
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		candidate, current string
		newer              bool
	}{
		{"1.2.4", "1.2.3", true},
		{"1.3.0", "1.2.9", true},
		{"2.0.0", "1.99.99", true},
		{"1.2.3", "1.2.3", false},
		{"1.2.2", "1.2.3", false},
		{"1.2.3", "dev", true},
		{"1.2.3-rc1", "1.2.3", false},
		{"v1.2.4", "1.2.3", false},
		{"1.02.4", "1.2.3", false},
		{"", "1.2.3", false},
	} {
		if got := newer(c.candidate, c.current); got != c.newer {
			t.Errorf("newer(%q, %q) = %v", c.candidate, c.current, got)
		}
	}
	if Version() != "dev" {
		t.Fatalf("test binary reports %q", Version())
	}
}
