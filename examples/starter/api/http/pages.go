package http

// The single-page app serves every page; each section's route is added here,
// requiring sign-in first, as its page is added. Account is AppKit's page: the
// person and their keys.
const (
	AccountPattern  = "GET /account"
	FrontendPattern = "/"
)
