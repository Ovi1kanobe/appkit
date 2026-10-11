// Package selfupdate replaces the running executable with a newer stable
// GitHub release. It needs nothing beyond the standard library.
//
// A release is a tag vX.Y.Z whose assets are <Name>-<os>-<arch> for each
// platform and checksums.txt in sha256sum format. The new binary must print
// its bare X.Y.Z for --version, which is checked before anything is replaced.
package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	apiOrigin        = "https://api.github.com"
	metadataTimeout  = 15 * time.Second
	downloadTimeout  = 5 * time.Minute
	versionTimeout   = 10 * time.Second
	maxMetadataBytes = 1 << 20   // 1 MiB of release JSON or checksums.
	maxAssetBytes    = 512 << 20 // 512 MiB binary.
)

// ErrCurrent reports that this build already is the latest release.
var ErrCurrent = errors.New("selfupdate: already the latest version")

// Version returns this build's version: the bare X.Y.Z of the git tag it was
// built at, or "dev" for any other build. Go stamps the tag into binaries
// built from a clean checkout, so no build flags are needed.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	version := strings.TrimPrefix(info.Main.Version, "v")
	if _, ok := parseVersion(version); !ok {
		return "dev"
	}
	return version
}

// Updater names the GitHub repository that publishes this program's releases.
// Token is optional for public repositories and is sent only to the GitHub API,
// never to the host that serves downloads. Client is optional.
type Updater struct {
	Repository string // owner/name
	Name       string // asset prefix: releases contain <Name>-<os>-<arch>
	Token      string
	Client     *http.Client
}

// Release is a stable release of the repository.
type Release struct {
	Version string // bare X.Y.Z
	Newer   bool   // than Version(); a dev build treats every release as newer
	assets  map[string]string
}

// Check returns the latest stable release. It touches nothing on disk.
func (updater Updater) Check(ctx context.Context) (Release, error) {
	if err := updater.validate(); err != nil {
		return Release{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	body, err := updater.get(ctx, apiOrigin+"/repos/"+updater.Repository+"/releases/latest", "application/vnd.github+json", maxMetadataBytes)
	if err != nil {
		return Release{}, err
	}
	var latest struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &latest); err != nil {
		return Release{}, fmt.Errorf("selfupdate: release metadata: %w", err)
	}
	version := strings.TrimPrefix(latest.Tag, "v")
	if _, ok := parseVersion(version); !ok || latest.Draft || latest.Prerelease {
		return Release{}, fmt.Errorf("selfupdate: latest release %q is not a stable version", latest.Tag)
	}
	release := Release{Version: version, Newer: newer(version, Version()), assets: map[string]string{}}
	for _, asset := range latest.Assets {
		release.assets[asset.Name] = asset.URL
	}
	return release, nil
}

// Update installs the latest stable release over executable, which is
// normally the result of os.Executable. Symlinks are resolved, the download
// is verified against checksums.txt, the new file must print the release
// version for --version, and the replacement is one atomic rename. Any
// failure leaves the current executable untouched. It returns the installed
// version, or ErrCurrent.
func (updater Updater) Update(ctx context.Context, executable string) (string, error) {
	release, err := updater.Check(ctx)
	if err != nil {
		return "", err
	}
	if !release.Newer {
		return "", ErrCurrent
	}
	target, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("selfupdate: executable: %w", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return "", fmt.Errorf("selfupdate: executable: %w", err)
	}
	assetName := updater.Name + "-" + runtime.GOOS + "-" + runtime.GOARCH
	assetURL, ok := release.assets[assetName]
	checksumsURL, haveChecksums := release.assets["checksums.txt"]
	if !ok || !haveChecksums {
		return "", fmt.Errorf("selfupdate: release %s has no %s with checksums.txt", release.Version, assetName)
	}
	metadataCtx, cancelMetadata := context.WithTimeout(ctx, metadataTimeout)
	defer cancelMetadata()
	checksums, err := updater.get(metadataCtx, checksumsURL, "application/octet-stream", maxMetadataBytes)
	if err != nil {
		return "", err
	}
	expected, err := checksumFor(checksums, assetName)
	if err != nil {
		return "", err
	}
	downloadCtx, cancelDownload := context.WithTimeout(ctx, downloadTimeout)
	defer cancelDownload()
	binary, err := updater.get(downloadCtx, assetURL, "application/octet-stream", maxAssetBytes)
	if err != nil {
		return "", err
	}
	if actual := sha256.Sum256(binary); !bytes.Equal(actual[:], expected) {
		return "", fmt.Errorf("selfupdate: %s does not match checksums.txt", assetName)
	}
	staged, err := stage(target, binary, info.Mode().Perm())
	if err != nil {
		return "", err
	}
	defer os.Remove(staged)
	if err := verifyVersion(ctx, staged, release.Version); err != nil {
		return "", err
	}
	if err := os.Rename(staged, target); err != nil {
		return "", fmt.Errorf("selfupdate: replace executable: %w", err)
	}
	return release.Version, nil
}

func (updater Updater) validate() error {
	owner, name, ok := strings.Cut(updater.Repository, "/")
	if !ok || owner == "" || name == "" || strings.ContainsAny(updater.Repository, " ?#") || strings.Count(updater.Repository, "/") != 1 {
		return fmt.Errorf("selfupdate: repository %q must be owner/name", updater.Repository)
	}
	if updater.Name == "" || strings.ContainsAny(updater.Name, "/ ") {
		return fmt.Errorf("selfupdate: name %q must be a bare file name", updater.Name)
	}
	return nil
}

// get fetches address, sending the token only while the request stays on the
// GitHub API origin. Downloads redirect elsewhere and must not carry it.
func (updater Updater) get(ctx context.Context, address, accept string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: %w", err)
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", updater.Name+"/"+Version())
	apiHost := request.URL.Host
	if updater.Token != "" && sameOrigin(request.URL, apiOrigin) {
		request.Header.Set("Authorization", "Bearer "+updater.Token)
	}
	client := updater.Client
	if client == nil {
		client = &http.Client{}
	}
	hop := *client
	hop.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if next.URL.Host != apiHost {
			next.Header.Del("Authorization")
		}
		return nil
	}
	response, err := hop.Do(request)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && sameOrigin(request.URL, apiOrigin) {
		return nil, fmt.Errorf("selfupdate: %s has no published release, or a token is needed to see it", updater.Repository)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("selfupdate: %s answered %s", request.URL.Host, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("selfupdate: read %s: %w", request.URL.Host, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("selfupdate: %s exceeds %d bytes", request.URL.Path, limit)
	}
	return body, nil
}

func sameOrigin(address *url.URL, origin string) bool {
	return address.Scheme+"://"+address.Host == origin
}

// checksumFor finds name in sha256sum output: "<hex>  <name>" per line.
func checksumFor(checksums []byte, name string) ([]byte, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		sum, err := hex.DecodeString(fields[0])
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("selfupdate: checksums.txt has a malformed entry for %s", name)
		}
		return sum, nil
	}
	return nil, fmt.Errorf("selfupdate: checksums.txt has no entry for %s", name)
}

// stage writes the new binary beside target, so the final rename never
// crosses a filesystem, with the current executable's permissions.
func stage(target string, binary []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".update-*")
	if err != nil {
		return "", fmt.Errorf("selfupdate: stage: %w", err)
	}
	staged := file.Name()
	_, writeErr := file.Write(binary)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		os.Remove(staged)
		return "", fmt.Errorf("selfupdate: stage: %w", err)
	}
	if err := os.Chmod(staged, mode|0o100); err != nil {
		os.Remove(staged)
		return "", fmt.Errorf("selfupdate: stage: %w", err)
	}
	return staged, nil
}

// verifyVersion runs the staged binary's --version and requires the exact
// release version, so a wrong or corrupt asset is never installed.
func verifyVersion(ctx context.Context, staged, version string) error {
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, staged, "--version").Output()
	if err != nil {
		return fmt.Errorf("selfupdate: new binary --version: %w", err)
	}
	if reported := strings.TrimSpace(string(output)); reported != version {
		return fmt.Errorf("selfupdate: new binary reports version %q, release is %s", reported, version)
	}
	return nil
}

// parseVersion accepts exactly X.Y.Z with plain decimal numbers.
func parseVersion(text string) ([3]uint64, bool) {
	var version [3]uint64
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return version, false
	}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return version, false
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return version, false
		}
		version[i] = number
	}
	return version, true
}

// newer reports whether candidate is a later stable version than current.
// A current that is not a stable version, such as dev, is older than any
// release; a candidate that is not stable is never newer.
func newer(candidate, current string) bool {
	next, ok := parseVersion(candidate)
	if !ok {
		return false
	}
	now, ok := parseVersion(current)
	if !ok {
		return true
	}
	return next != now && (next[0] > now[0] || next[0] == now[0] && (next[1] > now[1] || next[1] == now[1] && next[2] > now[2]))
}
