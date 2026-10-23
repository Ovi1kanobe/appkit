package api

import (
	"io"
	"net/http"
)

// DefaultBodyLimit is the request body size LimitBodies allows on a route with
// no limit of its own: plenty for a JSON body.
const DefaultBodyLimit = 1 << 20

// LimitBodies caps every request body at limit bytes, so no handler can be
// made to read without bound. identity's Router applies it once around every
// route; a server without one wraps its whole handler once. A handler that
// reads past the limit gets an *http.MaxBytesError, which WriteError answers
// with 413.
func LimitBodies(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Body != nil && request.Body != http.NoBody {
			request.Body = &limitedBody{ReadCloser: http.MaxBytesReader(writer, request.Body, limit), original: request.Body, writer: writer}
		}
		next.ServeHTTP(writer, request)
	})
}

// LimitBody gives one route its own limit, larger or smaller than LimitBodies'
// default, such as an upload. It may sit anywhere on the route's line before
// anything that reads the body: it caps the body LimitBodies received, not the
// one LimitBodies already capped. When two sit on one line, the one nearest
// the handler wins.
func LimitBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch body := request.Body.(type) {
		case *limitedBody:
			request.Body = &limitedBody{ReadCloser: http.MaxBytesReader(body.writer, body.original, limit), original: body.original, writer: body.writer}
		case nil:
		default:
			if body != http.NoBody {
				request.Body = &limitedBody{ReadCloser: http.MaxBytesReader(writer, body, limit), original: body, writer: writer}
			}
		}
		next.ServeHTTP(writer, request)
	})
}

// limitedBody is a body capped by LimitBodies or LimitBody. It keeps the
// original body and the writer LimitBodies saw, so a route's LimitBody can cap
// the original again instead of stacking a second limit.
type limitedBody struct {
	io.ReadCloser
	original io.ReadCloser
	writer   http.ResponseWriter
}
