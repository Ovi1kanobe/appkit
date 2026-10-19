// Sign-in state comes only from /auth/session; /auth/events reports the moment it ends.
// A failed refresh keeps the last signed-in state and marks it refreshFailed, so pages stay usable.
import { useSyncExternalStore } from "react"

export type User = { subject: string; email?: string }
// Present only when the person may give an API key at least one permission.
export type KeyOptions = { delegable: string[]; max_lifetime_seconds: number }
export type Session =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "signed-out" }
  | { status: "signed-in"; user: User; permissions: string[]; keys?: KeyOptions; refreshFailed: boolean }

let current: Session = { status: "loading" }
let events: EventSource | undefined
const listeners = new Set<() => void>()

function update(next: Session) {
  current = next
  for (const listener of listeners) listener()
}

function signedOut() {
  events?.close()
  events = undefined
  update({ status: "signed-out" })
}

function listenForSignOut() {
  if (events) return
  events = new EventSource("/auth/events")
  events.addEventListener("signed-out", signedOut)
  events.onerror = () => void refreshSession()
}

export async function refreshSession() {
  try {
    const response = await fetch("/auth/session", { cache: "no-store" })
    if (!response.ok) throw new Error(response.statusText)
    const body = (await response.json()) as { user: User | null; permissions: string[]; keys?: KeyOptions }
    if (!body.user) return signedOut()
    update({
      status: "signed-in",
      user: body.user,
      permissions: body.permissions,
      keys: body.keys,
      refreshFailed: false,
    })
    listenForSignOut()
  } catch {
    update(current.status === "signed-in" ? { ...current, refreshFailed: true } : { status: "unavailable" })
  }
}

export function useSession(): Session {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => current,
  )
}

// Pages render only while signed in, so they read the user through this.
export function useSignedIn() {
  const session = useSession()
  if (session.status !== "signed-in") throw new Error("useSignedIn requires a signed-in session")
  return {
    user: session.user,
    keys: session.keys,
    can: (permission: string) => session.permissions.includes(permission),
  }
}

refreshSession()
window.addEventListener("pageshow", (event) => event.persisted && void refreshSession())
document.addEventListener("visibilitychange", () => !document.hidden && void refreshSession())
