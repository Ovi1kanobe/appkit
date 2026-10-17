# AppKit

Small Go infrastructure building blocks and an explicit application architecture standard.
AppKit does not own your application: `main.go` constructs dependencies, mounts routes, and controls lifecycle.

Import the packages you need from `github.com/Ovi1kanobe/appkit`; there is no root package or global initialization.
Requires Go 1.26 or newer.

| Package | Owns |
| --- | --- |
| `api` | JSON responses, and system errors declared with the status they mean, so handlers never map errors |
| `identity` | OIDC discovery, cached JWKS verification, bearer authentication, browser sessions, context identity, back-channel logout, service calls between applications |
| `authz` | External group, and calling application, to application role to permission mapping |
| `realtime` | Authenticated WebSocket connections, subscriptions, safe writes, a coalescing publisher, cleanup |
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
`Declarations()` lists every variable declared so far, with its description, whether it is required, and its default; the `install` command uses it to ask for each one.

## Errors

A system declares each error a person can be shown with `api.Invalid`, `api.Forbidden`, `api.NotFound`, `api.Conflict`, or `api.Unavailable`, whose text is the sentence the person reads.
`api.Unavailable` is for an outside service that did not answer, so the person should try again later.
Handlers answer with `api.WriteJSON` and `api.WriteError`; the latter sends a declared error's sentence with its status, even when wrapped, and any other error as a logged 500 with a generic message.
An `api.Unavailable` error is also logged as a warning with everything it wraps, so the operator sees what did not answer.

```go
var ErrNotFound = api.NotFound("That note no longer exists.")

note, err := system.Get(ctx, id)
if err != nil {
    api.WriteError(writer, request, err) // 404 {"error":"That note no longer exists."}
    return
}
api.WriteJSON(writer, http.StatusOK, view)
```

## Request bodies

Wrap the mux once, at the end of the application's `routes`, so every route has a body limit and no handler reads without bound:

```go
return api.LimitBodies(api.DefaultBodyLimit, mux)
```

A route that needs another limit, such as an upload, puts `api.LimitBody(limit, handler)` anywhere on its line.
Handlers decode a body with `api.ReadJSON(request, &input)`, which reads one JSON value and nothing after it, and returns the error `api.WriteError` answers with 413 for a body over its limit or 400 for one that is not valid JSON.

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
`Require`, `Optional`, and `Bearer` attach the identity with `Permissions` resolved by the configured policy, never stored: from its groups for a person, and from the policy's client list for a calling application (see Service calls).
`identity.RequirePermission` answers 401 without an identity and 403 when `Identity.Can` is false; resource-level rules in the application use the same `Can`.
Browser middleware ignores bearer credentials; bearer middleware ignores cookies.
Bearer-only apps can use `identity.New` and `Verifier.Middleware` without any SQLite dependency; that identity carries no permissions.

Sign-in is `<a href="/auth/login">Sign in</a>`.
Sign-out is `<form method="post" action="/auth/logout"><button>Sign out</button></form>`.
An optional `next` parameter selects a local return path.
There is no automatic sign-in.

AppKit owns `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/backchannel`, `/auth/session`, and `/auth/events`.
The session endpoint returns `{ "user": null, "permissions": [] }` when signed out, otherwise the identity and permissions resolved through the application's policy.
`SessionConfig.OnSessionRequest`, when set, runs on each signed-in session request, which every page makes as it loads, so the app can record that the person is here; its result is added to that body as `app`, so pages get display names, preferences, or other per-person state in the same request.
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
An app that calls another one also has the `client_credentials` flow and lists the other app's client ID under its allowed resources (see Service calls).

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

## Install

`install.Installer` sets the running binary up as a systemd service on a Linux host; apps expose it as the `install` command, which runs as root:

```sh
curl -fsSLO https://github.com/<owner>/<app>/releases/latest/download/<app>-linux-amd64
sudo ./<app>-linux-amd64 install
```

It creates the system user `<app>`, copies the binary to `/opt/<app>/<app>`, puts both databases under `/var/lib/<app>`, writes a hardened unit, enables it, and starts the service.
An existing account with that name is used only when it is a dedicated system account, never root or one with a login shell.
The environment file `/etc/<app>/<app>.env` is root-only and filled in by asking for each declared variable, in declaration order, with Enter keeping an optional variable's default.
`APP_MASTER_KEY` is generated and `APP_ENV` is production, so neither is asked; the key is printed once when the command runs on a terminal, otherwise the summary says to copy it from the file.
A variable whose name ends in `_SECRET`, `_KEY`, `_TOKEN`, `_PASSWORD`, `_PASS`, `_PASSPHRASE`, `_CREDENTIALS`, `_URL`, or `_DSN` is not shown while typed.
Running `install` again keeps every value in the file, including a database path an operator moved, asks only for variables the binary now declares that the file lacks or leaves empty, rewrites the unit, and restarts the service.
Values an operator adds to the file by hand are kept; comments are not.

## Releases and self-update

`selfupdate.Version()` returns the bare `X.Y.Z` of the git tag the binary was built at, or `dev` for any other build; Go stamps it, so no build flags are needed.
`Updater.Check` returns the latest stable release and whether it is newer; `Updater.Update` downloads the `<name>-<os>-<arch>` asset, verifies it against the release's `checksums.txt`, runs its `--version`, and replaces the executable with one atomic rename.
A failed update leaves the current binary untouched, and a successful one never restarts the process.
A token is sent only to the GitHub API, never to the host that serves downloads.
Apps expose these as `version` and `update` commands.
For a private repository, `update` needs a GitHub token with read-only Contents access to that repository, from `--token` or `GITHUB_TOKEN`.
Keep it out of the app's environment file, which only the service reads; store it in a root-only file and read it when updating, so it never appears in a command line:

```sh
sudo sh -c 'GITHUB_TOKEN=$(cat /etc/<app>/github-token) /opt/<app>/<app> update' && sudo systemctl restart <app>
```

## Authorization

```go
policy, err := authz.New(
    map[string][]string{
        "builder": {"bots.write", "bots.start"},
        "auditor": {"bots.all.read"},
    },
    map[string][]string{"deployment-builders": {"builder"}},
    map[string][]string{"monitor": {"auditor"}}, // Rauthy clients of applications that call this one; nil when none
)
// Handle err at startup; pass policy to identity.SessionConfig, which resolves it onto every identity.
if viewer.Can("bots.write") { /* viewer is the identity.Identity from the request */ }
```

Multiple groups/roles union permissions; unknown groups and unlisted clients grant nothing; roles and permissions are returned in sorted order.
`policy.Resolve(groups, localRoles...)` returns an `authz.Actor` directly, and also accepts trusted application-owned role assignments, never unvalidated request values.
Permissions say what a role may do; the application's own resource rules decide which records that applies to.
Rauthy groups are shared by every application, so start each group name with the application name (`notes-admins`, `billing-admins`).

Applications keep their own profile of each person, keyed by `Identity.Subject` and refreshed through `SessionConfig.OnSessionRequest`.

## Service calls

An application calls another AppKit application as itself, never as a person, with an access token Rauthy issues through the client credentials grant.

```go
accounts, err := sessions.ServiceClient("accounts") // the other application's Rauthy client ID
// Handle err at startup; accounts is an *http.Client whose every request carries a current token.
```

The caller's Rauthy client is confidential, has the `client_credentials` flow, and lists the target's client ID under its allowed resources; Rauthy refuses any other resource with `invalid_target`, so which application may call which is decided in Rauthy, on the calling client.
A client token has no `sub`; Rauthy names the caller in `azp` and addresses the token to both the caller and the target through `aud`.
The target's `Bearer` middleware accepts it only because its own client ID is in that audience, so a token minted for one application is refused by every other.
It attaches an `Identity` with `Client` true and `Subject` the caller's client ID, and grants the permissions the policy's client list gives that ID; an unlisted client gets 403.
Read and write rules tell a calling application from a person with `Client`.
Tokens are renewed before they expire; disabling the caller's client in Rauthy, or removing the resource from it, ends its access within one token lifetime.
Keep Rauthy's `CLIENT_CREDENTIALS_MAP_SUB` at its default, off, so a client token is never mistaken for a person.
`identitytest` issues client tokens through `ClientToken` and serves `ServiceClient`, so service calls are tested without Rauthy.

## Realtime and frontend

`Hub` is a local connection registry with no hidden workers or message queues.
Applications call `Accept`, defer `Conn.Close`, authorize topics before `Subscribe`, and keep one read loop active.
`Conn.Keep` is that loop for a socket that only listens: it discards what arrives and pings every thirty seconds, so a dead socket on a quiet topic is noticed.
`Hub.Subscriber(topic)` is the whole handler for such a socket; mount it behind the topic's permission.
Once subscribed it sends `realtime.Ready`, `{"ready":true}`, so a page refetches only when it can no longer miss a change, and a test publishes only after reading it; a hand-written handler sends it right after `Subscribe`.
Concurrent writes are safe; writes and pings have a five-second ceiling, and failure removes the connection.
`PublishEach` asks a `View`, once per subscriber, what that person receives, so each person gets only their own view; it writes sequentially to a subscriber snapshot, and a write that misses its five-second ceiling closes that socket.
`Publisher` turns a system's changes into messages on one topic: pass its `Add` as the system's `onChange`, which never blocks and keeps the latest change per key in first-arrival order, merged by `Merge` when set, and start `Run`, which sends each subscriber their view of every pending change.
Its view function runs once per change and returns the `View`, so a lookup every subscriber needs runs once, and a slow subscriber is closed by its own write ceiling rather than costing the others the change.
When the view returns an error, `Run` logs it and tries the change again a second later, unless a newer change for its key has replaced it; so an error means a failure that can pass, such as a busy database, and nothing to send, such as an item that no longer exists, is a nil `View` with no error.
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
