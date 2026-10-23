# AppKit

Small Go infrastructure building blocks and an explicit application architecture standard.
AppKit does not own your application: `main.go` constructs dependencies, mounts routes, and controls lifecycle.

Import the packages you need from `github.com/Ovi1kanobe/appkit`; there is no root package or global initialization.
Requires Go 1.26 or newer.

| Package | Owns |
| --- | --- |
| `api` | JSON responses, and system errors declared with the status they mean, so handlers never map errors |
| `identity` | OIDC discovery, cached JWKS verification, the router that guards every route, browser sessions, context identity, back-channel logout, service calls between applications |
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

The router caps every request body at its `RouterConfig.BodyLimit`, so no handler reads without bound; `api.DefaultBodyLimit` suits JSON, and zero panics rather than meaning a hidden default.
A route that needs another limit, such as an upload, wraps its handler in `api.LimitBody(limit, handler)` on its line.
Handlers decode a body with `api.ReadJSON(request, &input)`, which reads one JSON value and nothing after it, and returns the error `api.WriteError` answers with 413 for a body over its limit or 400 for one that is not valid JSON.

## Routes and browser sessions

```go
sessionConfig := appKit.Sessions
sessionConfig.Policy = policy // application-owned authz rules
sessions, err := identity.NewSessions(ctx, sessionConfig)
// Handle err at startup.
defer sessions.Close()
router := sessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit}) // AppKit's /auth/ routes are already on it
router.Private("GET /api/notes", "notes.read", listNotes)
router.Private("GET /ws/status", "diagnostics.read", statusSocket)
router.Service("GET /api/status", "diagnostics.read", status)
router.Public("GET /api/health", health, identity.PublicOptions{Probe: true})
router.Public("GET /", pages) // the frontend, the one public subtree
server := &http.Server{Handler: router /* and timeouts */}
```

AppKit owns how routes are guarded, never which routes exist: the app's `routes` function mounts each one on the router, choosing its kind on its line.
A pattern is a method from `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`, one space, and a path with no host; a `GET` route also answers `HEAD`.
Paths under `/auth/` belong to AppKit, so the router refuses them.
A mount that breaks a rule, or a second `Sessions.Router` call, panics at startup with a message naming the line.
A route that differs signed in and signed out is two routes on two paths.

`Private` is for people: a session cookie, or a personal key in a `Bearer` header, holding the permission.
Signed out it answers 401, never a redirect, since the single-page app sends a signed-out person to sign in; without the permission it answers 403.
`Service` is for a Rauthy access token holding the permission, an application's (see Service calls) or a person's; it never accepts a session cookie or a key, and skips the Host check, since a browser never attaches the token by itself.
Both attach the identity with `Permissions` resolved by the configured policy, never stored: from its groups for a person, and from the policy's client list for a calling application.
Resource-level rules in the application use the same `Identity.Can`.
API and WebSocket errors from AppKit use the same `{"error": "..."}` body as applications.

`Public` is GET only, for anyone, and needs no permission.
Its handler sees no cookie, authorization, trailer, or URL userinfo, and `identity.FromContext` panics in it, because a public answer is the same for everyone.
It may stream with `http.Flusher`, but cannot hijack the connection.
A request to it with a `Bearer` credential answers 400, since the caller meant another route, and so does a WebSocket upgrade.
The only options are `PublicOptions{Probe: true}`, which serves any Host and drops credentials silently, for one health path a load balancer reaches by address, and `CrossOrigin: true`, which adds `Access-Control-Allow-Origin: *`.
Each public route is logged once at mount, so the log lists them.

Every response, Go's own 404 and 405 included, carries `Cache-Control: no-store`, which a handler may replace, `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`, and HSTS on an HTTPS origin.
Bearer-only services without sessions or SQLite can use `identity.New` and `Verifier.Middleware`, whose identity carries no permissions; it is not for AppKit apps.

Sign-in is `<a href="/auth/login">Sign in</a>`.
Sign-out is `<form method="post" action="/auth/logout"><button>Sign out</button></form>`.
An optional `next` parameter selects a local return path.
There is no automatic sign-in.

AppKit owns `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `POST /auth/backchannel`, `GET /auth/session`, `GET /auth/events`, `/auth/keys`, and `/auth/users/{subject}/keys`; a POST to a GET-only one answers 405.
The session endpoint returns `{ "user": null, "permissions": [] }` when signed out, otherwise the identity and permissions resolved through the application's policy, and `keys` with what the person may give a key (see Personal keys).
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
Raw cookies, key secrets, provider tokens, client secrets, and authorization headers are never persisted or logged by AppKit.

Use a dedicated local database file.
AppKit owns its schema, opens it with restrictive permissions, and holds an exclusive SQLite lock until `Close`.
A second process fails clearly.
Back up only after shutdown; network filesystems and multiple instances are unsupported.

Unsafe browser requests require the configured Origin or same-origin Fetch Metadata.
WebSocket upgrades require the exact Origin.
Plain HTML forms work without custom JavaScript headers.
Keep GET/HEAD/OPTIONS handlers free of mutations.
Use HTTPS for the configured public origin and provider endpoints, except on localhost.
Do not add CORS beyond a public route's option, or log callback query strings/credentials in proxies.

Back-channel notifications with `sid` end matching sessions only (and match `sub` too when supplied).
Subject-only notifications end all that user's sessions.
Replays are harmless, and durable logout records prevent racing callbacks from admitting revoked sessions.
Revocation/expiry cancels live request contexts and closes AppKit WebSockets with close code `4401` (`realtime.AuthenticationEnded`), so pages can tell it apart from a network drop.
Custom streaming handlers must honor their request contexts.

Sign-out ends only the app session.
Rauthy's own session is untouched, so signing in again may not ask for a password.
Logouts in Rauthy reach the app through back-channel logout.

Access tokens remain valid until expiry after logout: a service caller is cut off within one access-token lifetime, not instantly.
Service routes also bound request/WebSocket lifetime by token expiry.
Token groups remain the token's snapshot.

## Personal keys

A key is a personal API key a signed-in person makes for a tool, scoped to some of their own permissions, so the tool calls the app's routes as that person with `Authorization: Bearer ak_...`.
The policy's delegable permissions, the last argument of `authz.New`, say which permissions a key may ever carry; an app that lists none issues no keys, and the list never holds a permission that moves money, changes credentials or endpoints, or is irreversible.
A key gets the permissions its scopes name, as long as they are delegable and the policy still grants them to the holder's groups, captured at creation and refreshed at each sign-in; a key that would get none is refused.
A route behind a permission that is not delegable answers 403 to every key, so apps need no second check; when one permission would cover a route a key may call and one it may not, split the permission.
`Identity.KeyID` names the key on a request it made and is empty otherwise, so a write rule may refuse one case to keys.
A key lives at most `SessionConfig.KeyLifetime` from creation, thirty days by default and never more than ninety, so a leaked key dies on its own within a quarter.
AppKit owns `/auth/keys`: a person lists, makes, and revokes their own keys from a browser session, and a key cannot manage keys.
`GET /auth/keys` answers `{"keys": [{id, name, scopes, permissions, created_at, expires_at, last_used_at, revoked_at}]}`, newest first, where `permissions` is what the key gets now; `POST /auth/keys` takes `{name, scopes, lifetime_seconds}` and answers 201 with `{key, secret}`, the only time the secret is shown; `DELETE /auth/keys/{id}` answers 204 whether or not the key was live.
`/auth/session` for a key answers `user` with `key_id`, the key's `permissions`, and `key: {name, scopes, expires_at}`, and `OnSessionRequest` does not run; for a browser it adds `keys: {delegable, max_lifetime_seconds}` when the person may give a key something.
With `SessionConfig.KeyAdminPermission` set, `GET /auth/users/{subject}/keys` lists any person's keys, and `DELETE` on that path or on `/{id}` under it revokes all or one, behind that permission, so an admin page can end a disabled person's keys.
Every app keeps the starter's Account page at `/account`, where a person manages their keys.
Revocation and expiry cancel live requests and sockets like a session's end; a tool that sees close code `4401` or `signed-out` reads `/auth/session` again and reconnects, since the key may have been narrowed rather than ended.
Removing a person from the app's groups, or disabling them in Rauthy, does not end their keys: they are narrowed at the next sign-in, which a disabled account never makes, and die at expiry, so revoke them from the Account page or the admin route.
Rauthy logouts end sessions, never keys.
Only key hashes are stored; the secret is shown once at creation.
The session database still needs no backup, but a restore would resurrect revoked keys, and losing it loses every key.
Tools keep a key in a secrets store, send it only to the app's origin and only in the header, and an agent that reads untrusted content gets a read-only key.

## Rauthy

AppKit requires Rauthy 0.37 or later; earlier versions issue access tokens without the standard `at+jwt` type, so service routes reject them.
The app's Rauthy client, public or confidential, has `authorization_code`, PKCE `S256`, the scopes `openid`, `email`, and `groups`, and matching access and ID token signing algorithms.
Its redirect URI is exactly `<APP_ORIGIN>/auth/callback` and its back-channel logout URI is `<APP_ORIGIN>/auth/backchannel`, which Rauthy must be able to reach; wildcards are unnecessary.
A short token lifetime bounds how long service callers keep access after logout.
Access is granted through Rauthy groups named after the app, such as `example-members`; no SCIM setup is needed.
An app that calls another one also has the `client_credentials` flow and lists the other app's client ID under its allowed resources (see Service calls).

## Test an application

`identity/identitytest` starts a local fake Rauthy, so tests exercise the real sign-in, session, CSRF, and service paths without a live provider.

```go
provider := identitytest.NewProvider(t)
app := httptest.NewServer(nil) // its URL is the configured origin
sessions, err := identity.NewSessions(ctx, identity.SessionConfig{
    Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL, /* database, driver, policy */
})
app.Config.Handler = routes(sessions /* , systems */) // the router, then:
user := identitytest.User{Subject: "alice", Groups: []string{"observers"}}
cookie := provider.SignIn(t, app.URL, user)  // session cookie for browser routes
token := provider.AccessToken(t, user)       // Authorization: Bearer token for service routes
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
- **Backups:** back up the application's own database, never together with its master key; the session database needs none, since losing it only signs everyone out and loses every personal key, and a restore would resurrect revoked keys.

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
    []string{"bots.all.read"},                   // permissions a person may give a personal key; nil when the app issues none
)
// Handle err at startup; pass policy to identity.SessionConfig, which resolves it onto every identity.
if viewer.Can("bots.write") { /* viewer is the identity.Identity from the request */ }
```

Multiple groups/roles union permissions; unknown groups and unlisted clients grant nothing; roles and permissions are returned in sorted order.
`policy.Resolve(groups, localRoles...)` returns an `authz.Actor` directly, and also accepts trusted application-owned role assignments, never unvalidated request values.
`policy.ResolveKey(groups, scopes)` returns what a personal key gets: its scopes, kept only where delegable and granted to the holder's groups; `policy.Delegable()` lists the delegable permissions.
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
The target's route, mounted with `router.Service`, accepts it only because the target's own client ID is in that audience, so a token minted for one application is refused by every other.
It attaches an `Identity` with `Client` true and `Subject` the caller's client ID, and grants the permissions the policy's client list gives that ID; an unlisted client gets 403.
Read and write rules tell a calling application from a person with `Client`.
Tokens are renewed before they expire; disabling the caller's client in Rauthy, or removing the resource from it, ends its access within one token lifetime.
Keep Rauthy's `CLIENT_CREDENTIALS_MAP_SUB` at its default, off, so a client token is never mistaken for a person.
A caller that reaches the target on an internal address still uses TLS, or a network segment trusted as much, since the token is a bearer credential.
A public Rauthy client lets a person mint an access token for themselves, which a service route serves with every permission their groups grant, bypassing the delegable list and scopes that limit a personal key; mount a route as service only when that is acceptable.
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
When the view returns an error, `Run` logs it and tries the change again a second later, unless a newer change for its key has replaced it; so an error means a failure that can pass, such as a busy database. An item that no longer exists is not an error: the view returns a `View` that sends its removal, and a nil `View` sends nothing at all.
It provides no durability, replay, ordering across concurrent publishers, or cross-process delivery.
Apps explicitly call `Hub.Close` during shutdown because HTTP shutdown does not close upgraded sockets.

Mount `frontend.New(files, frontend.Config{HashedAssets: "assets"})` as the public catch-all, `router.Public("GET /", pages)`, the app's one public subtree.
Files are read per request, so `os.DirFS` serves edits immediately in development; embed them for production.
Backend namespaces never receive the SPA fallback, even when their route is missing.
Existing files are served directly; missing paths under the hashed assets folder, or with file extensions, return 404.
Extensionless paths are SPA routes: a missing one gets the shell rather than 404, except under the hashed assets folder, where only content-hashed files belong.
`HashedAssets` names the folder whose files are named by content hash, as Vite's `assets` already is: they are sent as immutable for a year, so put nothing else there.
Every other file, `index.html` and the SPA fallback included, is sent with `Cache-Control: no-cache` and an ETag, so updates are seen and unchanged files answer 304; with the zero `Config`, that includes the assets.
`http.ServeContent` drops `Cache-Control` from a 416 for an unsatisfiable range, so that answer carries no cache policy.
A compression middleware in front of the frontend would have to weaken the ETag to `W/`, because the compressed bytes differ.
PWA files such as `manifest.webmanifest` and `sw.js` are ordinary root assets; `.webmanifest` is served as `application/manifest+json`, since Go has no type for it.
A service worker must never cache or answer backend namespaces.
Use an embedded, trusted filesystem; arbitrary filesystem adapters can have their own symlink semantics.
AppKit owns how routes are guarded, never which routes exist, and adds no frontend toolchain.
