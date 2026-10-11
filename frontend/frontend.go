// Package frontend serves embedded assets with a conservative SPA fallback.
package frontend

import (
	"bytes"
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
			http.ServeContent(writer, request, name, time.Time{}, bytes.NewReader(data))
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
		writer.Header().Set("Cache-Control", "no-cache")
		index, err := fs.ReadFile(files, "index.html")
		if err != nil {
			http.Error(writer, "frontend unavailable", http.StatusInternalServerError)
			return
		}
		http.ServeContent(writer, request, "index.html", time.Time{}, bytes.NewReader(index))
	}), nil
}
