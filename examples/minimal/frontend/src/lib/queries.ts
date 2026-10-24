// Every server resource the pages read, one query each. Mutations invalidate
// these keys and WebSocket messages update them, so pages never fetch directly.
import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api"

export type Note = { id: number; text: string; author_email?: string; mine: boolean; created_at: string }
export type KeyStatus = { set: boolean; last_four?: string; updated_at?: string }
// An API key the person made. permissions is what it gets now; fewer than its scopes means it was narrowed.
export type ApiKey = {
  id: string
  name: string
  scopes: string[]
  permissions: string[]
  created_at: string
  expires_at: string
  last_used_at?: string
  revoked_at?: string
}

export const notesKey = ["notes"] as const
export const emailKeyKey = ["email-key"] as const
export const apiKeysKey = ["keys"] as const

export function useNotes(enabled: boolean) {
  return useQuery({ queryKey: notesKey, queryFn: () => api<Note[]>("/api/notes"), enabled })
}

export function useEmailKey(enabled: boolean) {
  return useQuery({ queryKey: emailKeyKey, queryFn: () => api<KeyStatus>("/api/email/key"), enabled })
}

export function useApiKeys(enabled: boolean) {
  return useQuery({
    queryKey: apiKeysKey,
    queryFn: async () => (await api<{ keys: ApiKey[] }>("/auth/keys")).keys,
    enabled,
  })
}
