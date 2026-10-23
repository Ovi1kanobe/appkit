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

// New accepts a filesystem rooted at compiled frontend output (normally fs.Sub
// of an embed.FS). Backend routes must be registered on the application's router.
// Paths with an extension, /assets, and reserved backend namespaces never fall back.
// Files are read per request, so os.DirFS serves edits immediately in development.
func New(files fs.FS) (http.Handler, error) {
	if _, err := fs.Stat(files, "index.html"); err != nil {
		return nil, fmt.Errorf("frontend: index.html: %w", err)
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
			// Vite names files under /assets by content hash, so they never change.
			// Everything else, index.html included, is revalidated against its ETag.
			cacheControl := "no-cache"
			if first == "assets" {
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
		if first == "assets" || path.Ext(name) != "" {
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
