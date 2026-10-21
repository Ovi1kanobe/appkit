# AppKit example requirements

## Summary
A small reference app for AppKit: shared notes, live process status, and one stored credential.
It is used by AppKit developers to see every rule working.

## Name
- App name: example, used as the prefix of every group, such as `example-members`.
- Display title: AppKit example.
- Binary: appkit-example.
- Repository: Ovi1kanobe/appkit.

## Sections
| Section | What it does |
| --- | --- |
| Notes | Shared short notes; members add notes, and only a note's author deletes it; changes appear live |
| Dashboard | Live process uptime |
| Settings | Admins set the email provider's API key, stored encrypted and never shown again |

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

## Decisions
- Status is also served to bearer clients at `/api/status`.

## Out of scope
- Sending email.
