package http

// The single-page app serves every page; these routes require sign-in first.
// Account is AppKit's page: the person and their keys.
const (
	DashboardPattern = "GET /dashboard"
	SettingsPattern  = "GET /settings"
	AccountPattern   = "GET /account"
	FrontendPattern  = "/"
)
