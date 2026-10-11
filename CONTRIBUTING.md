# Contributing to AppKit

Read `README.md` before changing code.
AppKit supplies independent infrastructure packages, not an application runtime.

## Scope

- Keep the library small; adding a folder needs a very good reason and the maintainer's approval.
- Discuss any public API change before implementing it; developer experience comes first.
- Each package is usable alone, with no root package or global initialization.
- Prefer ordinary Go, explicit constructors, and small concrete types.
- No service locator, hidden DI, `init` registration, automatic discovery, plugin system, domain abstraction, generic database or repository, or lifecycle framework.
- Add no architectural pattern or interface without a concrete requirement.
- Keep `README.md` true: update it with every architectural change.
- Keep the examples in `examples/` working; tell the maintainer when a change affects how apps are built.

## Imports

- Packages never import application code.
- An AppKit package imports another only with approval.
- `config` is a level above: it may import the packages it configures, and they never import it.
- Approved exceptions: `identity` → `authz`, `realtime` → `identity`.
- Propose an exception when it makes things simpler or easier to understand.

## Behavior to preserve

- Rauthy 0.37 or later is the sole authentication authority; it issues `at+jwt` access tokens, and the OIDC subject is the canonical ID.
- `authz` maps groups to roles and unions their permissions; unmapped groups confer nothing.
- `identity.RequirePermission` checks coarse permissions only; resource-level rules belong to applications.
- Session-specific back-channel notices end that session; subject-only notices end all of the subject's sessions; durable logout records reject racing callbacks.
- Expiry and revocation cancel request contexts; `realtime` closes those connections and `/auth/events` notifies pages.
- The session database is exclusively locked for its lifetime; its schema is versioned, migrates forward, and an older AppKit refuses a newer one.
- `realtime.Hub` is a local connection registry with no hidden workers, queues, durability, or cross-process delivery.
- `frontend` never applies the SPA fallback to backend namespaces; missing assets return 404.
- No router, CORS policy, or frontend toolchain.

## Before submitting

- Keep security and boundary tests; unit tests use local fixtures and need no public internet.
- Run `gofmt`, `go vet ./...`, and `go test -race ./...` in the root.
- Run an example's `make test` when that example changes, or when you change an AppKit API it uses.
