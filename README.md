# AppKit

Small Go infrastructure building blocks and an explicit application architecture standard.
AppKit does not own your application: `main.go` constructs dependencies, mounts routes, and controls lifecycle.

Import the packages you need from `github.com/Ovi1kanobe/appkit`; there is no root package or global initialization.
Requires Go 1.26 or newer.

| Package | Owns |
| --- | --- |
| `identity` | OIDC discovery, cached JWKS verification, bearer authentication, browser sessions, context identity, back-channel logout |
| `authz` | External group to application role to permission mapping |
| `realtime` | Authenticated WebSocket connections, subscriptions, safe writes, cleanup |
| `frontend` | Embedded asset serving and conservative SPA fallback |
| `config` | Declared environment variables, reported all at once when missing or invalid |
| `encryption` | AES-256-GCM encryption of stored credentials with the application's master key |
| `schema` | Opens the application database with AppKit's SQLite settings; embedded migrations applied per system and refused on a newer database |
| `selfupdate` | The build's version from its git tag, and replacement of the running binary with a verified newer GitHub release |

## Start an application

Copy `examples/starter`, the empty app every app begins as.
`examples/minimal` is a small complete app; fill in its `.env` from `.env.example` and run `make -C examples/minimal dev`.

Declare every environment variable through `config`, then call `Check` once so startup reports all missing or invalid values together.

```go
environment := config.New()
appKit := environment.AppKit(config.Defaults{}) // every AppKit variable
if err := environment.Check(); err != nil {
    log.Fatal(err) // lists every missing or invalid variable; in development, logs each default in use
}
```

| Variable | Required | Purpose |
| --- | --- | --- |
| `RAUTHY_ISSUER` | yes | Rauthy issuer URL exactly as Rauthy reports it, including any trailing slash |
| `RAUTHY_CLIENT_ID` | yes | Rauthy client ID |
| `RAUTHY_CLIENT_SECRET` | confidential clients | Rauthy client secret |
| `APP_ORIGIN` | yes | Public origin users open, such as `https://app.example.com` or `http://localhost:8080` |
| `APP_MASTER_KEY` | yes | Base64 key that encrypts stored credentials; create with `openssl rand -base64 32` |
| `APP_ENV` | no, default `production` | `development` serves the frontend from disk and logs each default in use |
| `LISTEN_ADDRESS` | no, default `127.0.0.1:8080` | Address the server listens on |
| `DATABASE_PATH` | no, default `app.sqlite` | Application database file |
| `SESSION_DATABASE` | no, default `appkit-sessions.sqlite` | AppKit session database file |

Environment variables hold deployment values and secrets only; everything else, including roles and permissions, belongs in code.

## Browser sessions

```go
sessionConfig := appKit.Sessions
sessionConfig.Policy = policy // application-owned authz rules
sessions, err := identity.NewSessions(ctx, sessionConfig)
// Handle err at startup.
defer sessions.Close()
sessions.Routes(mux)
mux.Handle("GET /{$}", sessions.Optional(home))
mux.Handle("GET /dashboard", sessions.Require(dashboard))
mux.Handle("GET /ws/status", sessions.Require(identity.RequirePermission("diagnostics.read", socketHandler)))
mux.Handle("GET /api/status", sessions.Bearer(identity.RequirePermission("diagnostics.read", apiHandler)))
```

`Require` redirects signed-out HTML navigation to Rauthy and returns 401 for API/WebSocket requests.
API and WebSocket errors from AppKit use the same `{"error": "..."}` body as applications.
`Require`, `Optional`, and `Bearer` attach the identity with `Permissions` resolved from its groups by the configured policy, never stored.
`identity.RequirePermission` answers 401 without an identity and 403 when `Identity.Can` is false; resource-level rules in the application use the same `Can`.
Browser middleware ignores bearer credentials; bearer middleware ignores cookies.
Bearer-only apps can use `identity.New` and `Verifier.Middleware` without any SQLite dependency; that identity carries no permissions.

Sign-in is `<a href="/auth/login">Sign in</a>`.
Sign-out is `<form method="post" action="/auth/logout"><button>Sign out</button></form>`.
An optional `next` parameter selects a local return path.
There is no automatic sign-in.

AppKit owns `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/backchannel`, `/auth/session`, and `/auth/events`.
The session endpoint returns `{ "user": null, "permissions": [] }` when signed out, otherwise the identity and permissions resolved through the application's policy.
`SessionConfig.AppInfo`, when set, adds its result to that body as `app`, so pages get display names, preferences, or other per-person state in the same request.
The event stream emits `signed-out` when the session ends.
A single-page app reads `/auth/session` for its state and listens to `/auth/events` to switch to signed out immediately.

Sessions default to eight hours, fixed from sign-in.
Set `Lifetime` to change this.
Activity and restarts never extend expiry.
Groups are captured at sign-in; changes apply on the next sign-in.
A person with none of the application's groups is refused at sign-in and gets no session.
For urgent removal, end the person's session in Rauthy.
There is no SCIM, and a refresh token, if Rauthy issues one, is discarded unused.

Only opaque session cookies reach the browser; provider tokens stay on the server.
Cookies are HttpOnly, SameSite=Lax, and Secure with the `__Host-` prefix on HTTPS.
HTTP is allowed only on localhost/loopback.
Only cookie hashes are stored in SQLite.
Raw cookies, provider tokens, client secrets, and authorization headers are never persisted or logged by AppKit.

Use a dedicated local database file.
AppKit owns its schema, opens it with restrictive permissions, and holds an exclusive SQLite lock until `Close`.
A second process fails clearly.
Back up only after shutdown; network filesystems and multiple instances are unsupported.

Unsafe browser requests require the configured Origin or same-origin Fetch Metadata.
WebSocket upgrades require the exact Origin.
Plain HTML forms work without custom JavaScript headers.
Keep GET/HEAD/OPTIONS handlers free of mutations.
Use HTTPS for the configured public origin and provider endpoints, except on localhost.
Do not add permissive CORS or log callback query strings/credentials in proxies.

Back-channel notifications with `sid` end matching sessions only (and match `sub` too when supplied).
Subject-only notifications end all that user's sessions.
Replays are harmless, and durable logout records prevent racing callbacks from admitting revoked sessions.
Revocation/expiry cancels live request contexts and closes AppKit WebSockets with close code `4401` (`realtime.AuthenticationEnded`), so pages can tell it apart from a network drop.
Custom streaming handlers must honor their request contexts.

Sign-out ends only the app session.
Rauthy's own session is untouched, so signing in again may not ask for a password.
Logouts in Rauthy reach the app through back-channel logout.

Bearer access tokens remain valid until expiry after logout: a bearer client is cut off within one access-token lifetime, not instantly.
Bearer middleware also bounds request/WebSocket lifetime by token expiry.
Token groups remain the token's snapshot.

## Rauthy

AppKit requires Rauthy 0.37 or later; earlier versions issue access tokens without the standard `at+jwt` type, so bearer routes reject them.
The app's Rauthy client, public or confidential, has `authorization_code`, PKCE `S256`, the scopes `openid`, `email`, and `groups`, and matching access and ID token signing algorithms.
Its redirect URI is exactly `<APP_ORIGIN>/auth/callback` and its back-channel logout URI is `<APP_ORIGIN>/auth/backchannel`, which Rauthy must be able to reach; wildcards are unnecessary.
A short token lifetime bounds how long bearer clients keep access after logout.
Access is granted through Rauthy groups named after the app, such as `example-members`; no SCIM setup is needed.

## Test an application

`identity/identitytest` starts a local fake Rauthy, so tests exercise the real sign-in, session, CSRF, and bearer paths without a live provider.

```go
provider := identitytest.NewProvider(t)
app := httptest.NewServer(nil) // its URL is the configured origin
sessions, err := identity.NewSessions(ctx, identity.SessionConfig{
    Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL, /* database, driver, policy */
})
// Mount routes on app.Config.Handler, then:
user := identitytest.User{Subject: "alice", Groups: []string{"observers"}}
cookie := provider.SignIn(t, app.URL, user)  // session cookie for browser routes
token := provider.AccessToken(t, user)       // Authorization: Bearer token for bearer routes
```

See `TestRoutes` in `examples/minimal/main_test.go` for a complete example.
Handlers alone can be tested with `identity.WithContext`.

## Upgrade

AppKit is versioned with Git tags; each GitHub release lists what it adds and changes.
Update an application with:

```sh
go get github.com/Ovi1kanobe/appkit@latest
go mod tidy
```

Read the release notes for every version in between, then run your tests.
The session database records its schema version and is migrated forward at startup; an older AppKit refuses a database written by a newer one, so roll back the binary and session database together.

## Operating

An app is one process listening on loopback behind a TLS reverse proxy, with `APP_ORIGIN` set to the public origin.

- **One instance:** the session database is exclusively locked, so a second process fails to start and every restart is a short outage.
- **Rauthy at startup:** discovery runs at startup, so the application exits while Rauthy is unreachable; let the service manager restart it.
- **Host header:** the proxy must pass the original `Host`, or AppKit answers 421; WebSocket upgrades also need the `Upgrade` and `Connection` headers.
- **Event stream:** `/auth/events` is a long-lived response; disable proxy buffering for it (AppKit sends `X-Accel-Buffering: no`).
- **Logs:** never log query strings for `/auth/callback`, because they contain one-time authorization codes.
- **Secrets:** `RAUTHY_CLIENT_SECRET` and `APP_MASTER_KEY` are read from the environment and belong in a protected environment file, never in the repository.
- **Master key:** give each application its own, and store a copy in a password manager before the app first encrypts anything; losing it loses every stored credential.
- **Backups:** back up the application's own database, never together with its master key; the session database needs none, since losing it only signs everyone out.

## Releases and self-update

`selfupdate.Version()` returns the bare `X.Y.Z` of the git tag the binary was built at, or `dev` for any other build; Go stamps it, so no build flags are needed.
`Updater.Check` returns the latest stable release and whether it is newer; `Updater.Update` downloads the `<name>-<os>-<arch>` asset, verifies it against the release's `checksums.txt`, runs its `--version`, and replaces the executable with one atomic rename.
A failed update leaves the current binary untouched, and a successful one never restarts the process.
A token is sent only to the GitHub API, never to the host that serves downloads.
Apps expose these as `version` and `update` commands.

## Authorization

```go
policy, err := authz.New(
    map[string][]string{
        "builder": {"bots.write", "bots.start"},
        "auditor": {"bots.all.read"},
    },
    map[string][]string{"deployment-builders": {"builder"}},
)
// Handle err at startup; pass policy to identity.SessionConfig, which resolves it onto every identity.
if viewer.Can("bots.write") { /* viewer is the identity.Identity from the request */ }
```

Multiple groups/roles union permissions; unknown groups grant nothing; roles and permissions are returned in sorted order.
`policy.Resolve(groups, localRoles...)` returns an `authz.Actor` directly, and also accepts trusted application-owned role assignments, never unvalidated request values.
Permissions say what a role may do; the application's own resource rules decide which records that applies to.
Rauthy groups are shared by every application, so start each group name with the application name (`notes-admins`, `billing-admins`).

Applications keep their own profile of each person, keyed by `Identity.Subject` and refreshed through `SessionConfig.AppInfo`.

## Realtime and frontend

`Hub` is a local connection registry with no hidden workers or message queues.
Applications call `Accept`, defer `Conn.Close`, keep one read loop active, and authorize topics before subscribing.
Concurrent writes are safe; writes/pings have a five-second ceiling, and failure removes the connection.
Call `Ping` only while a read loop is active.
`Publish` writes sequentially to a subscriber snapshot; give it a total deadline and coalesce upstream when appropriate.
`PublishEach` asks a function, once per subscriber, what that person receives, so each person gets only their own view; `Publish` sends everyone the same data.
It provides no durability, replay, ordering across concurrent publishers, or cross-process delivery.
Apps explicitly call `Hub.Close` during shutdown because HTTP shutdown does not close upgraded sockets.

Mount `frontend.New(files)` at `/` after explicit backend handlers in your router.
Files are read per request, so `os.DirFS` serves edits immediately in development; embed them for production.
Backend namespaces never receive the SPA fallback, even when their route is missing.
Existing assets are served directly; missing `/assets/*` paths or paths with file extensions return 404.
Extensionless paths are SPA routes, so put extensionless static assets under `/assets`.
PWA files such as `manifest.webmanifest` and `sw.js` are ordinary root assets; `.webmanifest` is served as `application/manifest+json`, since Go has no type for it.
A service worker must never cache or answer backend namespaces, and `index.html` is sent with `Cache-Control: no-cache` so updates are seen.
Use an embedded, trusted filesystem; arbitrary filesystem adapters can have their own symlink semantics.
The package adds no router, CORS policy, or frontend toolchain.
