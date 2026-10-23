# AppKit example requirements

## Summary
A small reference app for AppKit: shared notes, live process status, and one stored credential.
It is used by AppKit developers to see every rule working.

## Problem
AppKit developers need one small app that exercises every rule in APPS.md, so a rule can be checked against running code instead of prose.
Without it, each new app is the first test of the rules.

## User stories

### 1. Share a note (P1)
A member opens Notes, adds a short note, and sees it in the shared list with everyone else's; the author, and only the author, removes it later.
- Why this priority: it is the smallest complete path through a system, its routes, access rules, a page, and live updates.
- Independent test: sign in as two members, add a note as one, see it appear for the other without a refresh, and delete it as its author only.
- Acceptance scenarios:
    1. Given a signed-in member, when they add a note of 1 to 500 characters, then it appears at the top of every open Notes page.
    2. Given a note by another member, when a member tries to delete it, then the app refuses with 403 and the note stays.
    3. Given an empty note or one over 500 characters, when it is submitted, then the app answers 400 with the sentence the person reads.

### 2. Watch the process (P2)
A member opens the Dashboard and sees how long the process has been running, updating live.
- Why this priority: it shows a system without tables and a service route for another app.
- Independent test: open the Dashboard and watch the uptime advance; call `/api/status` with a client token.
- Acceptance scenarios:
    1. Given a signed-in member, when they open the Dashboard, then the uptime shows and keeps advancing without a refresh.
    2. Given a calling app with the `monitor` role, when it calls `/api/status` with its token, then it receives the uptime as JSON.

### 3. Set the email key (P3)
An admin enters the email provider's API key once on Settings and sees that it is set and its last four characters, never the key itself.
- Why this priority: it shows a stored credential, encryption, and a write-only field.
- Independent test: set a key as admin, reload, see "set" and the last four characters; a member cannot open Settings.
- Acceptance scenarios:
    1. Given a signed-in admin, when they save a key, then the page shows it is set and its last four characters.
    2. Given a saved key, when any route is read, then the key itself is never in a response.

## Edge cases
- What happens when a note's author is deleted from Rauthy? The note stays, attributed by subject.
- What happens when the WebSocket drops? The page refetches on reconnect and misses nothing.

## Functional requirements
- FR-001: The app must keep a shared list of notes with author and time.
- FR-002: A member must be able to add a note of 1 to 500 characters and delete their own.
- FR-003: The app must push every note change to every open Notes page.
- FR-004: The app must report process uptime to members and to a calling app.
- FR-005: An admin must be able to store the email provider's API key, encrypted, and see only whether it is set and its last four characters.

## Key entities
- Note: text, author by subject, created time; belongs to one person; a note a visitor posted belongs to the public subject, and no member may delete it.
- Profile: a signed-in person's subject and email, recorded at every session request.
- Email settings: one row holding the encrypted API key.

## Success criteria
- SC-001: Every rule in APPS.md has at least one line of this app that shows it.
- SC-002: A note added by one person appears for another within one second.
- SC-003: `make test` passes in under two minutes with no internet.

## Assumptions
- One organisation; every member sees every note.
- The email provider is never called; only its key is stored.

## Name
- App name: example, used as the prefix of every group, such as `example-members`.
- Display title: AppKit example.
- Binary: appkit-example.
- Repository: Ovi1kanobe/appkit.

## Sections
| Section | What it does | Stories |
| --- | --- | --- |
| Notes | Shared short notes; members add notes, and only a note's author deletes it; changes appear live | 1 |
| Dashboard | Live process uptime | 2 |
| Settings | Admins set the email provider's API key, stored encrypted and never shown again | 3 |

## Groups
| Group | Role | Who | Can |
| --- | --- | --- | --- |
| `example-members` | `member` | Everyone using the example | Read every note, add notes, delete their own, see the dashboard |
| `example-admins` | `admin` | Example administrators | Set the email provider API key |

## Keys
- Delegable: `notes.read`, so a tool can read notes for ninety days at most without being able to add or delete any.
- Admin revoke: none.

## Branding
- Logo: none; the title only.
- Tone: minimal.
- Palette: neutral base.
- Accent color: shadcn's neutral default.
- Typography: the default, sans headings.
- Density: generous.
- Shape: shadcn's default radius.
- Dark mode: follow the system with a toggle.

## Platforms
- linux/amd64, linux/arm64.

## Outside services
- An email provider: its API key is entered on the Settings page; the example never calls it.

## Other apps
- Called by a monitoring app, client `monitor`, for the process status at `/api/status`.

## Public routes
| Route | Accepts | Fields | Who calls it and why |
| --- | --- | --- | --- |
| `GET /api/notes/public` | | `id`, `text`, `created_at` | An office wall display, which shows the latest notes without anyone signing in |
| `POST /api/notes/public` | `text` | `id`, `text`, `created_at` | A visitor page on any origin, which lets someone who is not signed in leave a note |

## Decisions
- Status is also served to calling apps at `/api/status`, instead of a separate monitoring app, because the example must show a service route.
- Notes are also served signed out at `/api/notes/public`, because the example must show a public data route.
- The public notes route allows 60 requests a minute per address, enough for a wall display and too few to flood it, and any origin may read it, so the visitor page can show the list.
- Visitors post notes signed out at `POST /api/notes/public`, because the example must show a public write; it accepts any origin, since the visitor page lives on another site, and allows 5 posts a minute per address, enough for a person and too few to flood the list.

## Out of scope
- Sending email.
