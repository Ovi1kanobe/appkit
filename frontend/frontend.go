// Package frontend serves embedded assets with a conservative SPA fallback.
package frontend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// Config says how New serves the build output.
type Config struct {
	// HashedAssets names the folder whose files are named by content hash,
	// such as Vite's "assets": they are sent as immutable for a year, and a
	// missing path under it answers 404 instead of the app shell. Empty, no
	// folder is immutable, and every file is revalidated against its ETag.
	HashedAssets string
}

// New accepts a filesystem rooted at compiled frontend output (normally fs.Sub
// of an embed.FS), and is mounted as the app's public catch-all, GET /.
// Paths with an extension, the hashed assets folder, and reserved backend
// namespaces never fall back to the shell.
// Files are read per request, so os.DirFS serves edits immediately in development.
func New(files fs.FS, config Config) (http.Handler, error) {
	if _, err := fs.Stat(files, "index.html"); err != nil {
		return nil, fmt.Errorf("frontend: index.html: %w", err)
	}
	if config.HashedAssets != "" && (!fs.ValidPath(config.HashedAssets) || config.HashedAssets == ".") {
		return nil, fmt.Errorf("frontend: hashed assets folder %q is not a folder path such as \"assets\"", config.HashedAssets)
	}
	inHashedAssets := func(name string) bool {
		return config.HashedAssets != "" && (name == config.HashedAssets || strings.HasPrefix(name, config.HashedAssets+"/"))
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(request.URL.Path, "/")
		for _, part := range strings.Split(name, "/") {
			if part == "." || part == ".." || strings.ContainsAny(part, "\\\x00") {
				http.NotFound(writer, request)
				return
			}
		}
		first, _, _ := strings.Cut(name, "/")
		if first == "api" || first == "ws" || first == "auth" || strings.HasPrefix(first, "__") {
			http.NotFound(writer, request)
			return
		}
		if name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) && !strings.HasSuffix(name, "/") {
			http.NotFound(writer, request)
			return
		}
		data, readErr := fs.ReadFile(files, name)
		if readErr == nil {
			// Go has no built-in type for web app manifests.
			if path.Ext(name) == ".webmanifest" {
				writer.Header().Set("Content-Type", "application/manifest+json")
			}
			// Files in the hashed assets folder are named by content hash, so they
			// never change. Everything else, index.html included, is revalidated
			// against its ETag.
			cacheControl := "no-cache"
			if inHashedAssets(name) {
				cacheControl = "public, max-age=31536000, immutable"
			}
			serveWithCacheHeaders(writer, request, name, data, cacheControl)
			return
		}
		if !errors.Is(readErr, fs.ErrNotExist) {
			// Directories may be SPA routes, but never expose directory listings.
			info, statErr := fs.Stat(files, strings.TrimSuffix(name, "/"))
			if statErr != nil || !info.IsDir() {
				http.NotFound(writer, request)
				return
			}
		}
		if inHashedAssets(name) || path.Ext(name) != "" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		index, err := fs.ReadFile(files, "index.html")
		if err != nil {
			http.Error(writer, "frontend unavailable", http.StatusInternalServerError)
			return
		}
		serveWithCacheHeaders(writer, request, "index.html", index, "no-cache")
	}), nil
}

// serveWithCacheHeaders sets Cache-Control and an ETag from the content hash on
// every served response; files carry no modification time, so the ETag is what
// lets ServeContent answer a matching If-None-Match with 304.
func serveWithCacheHeaders(writer http.ResponseWriter, request *http.Request, name string, data []byte, cacheControl string) {
	writer.Header().Set("Cache-Control", cacheControl)
	contentHash := sha256.Sum256(data)
	// 128 bits of the hash is ample for change detection and keeps the header short.
	writer.Header().Set("ETag", `"`+hex.EncodeToString(contentHash[:16])+`"`)
	http.ServeContent(writer, request, name, time.Time{}, bytes.NewReader(data))
}
