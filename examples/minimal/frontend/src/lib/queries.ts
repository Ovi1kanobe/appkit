// Every server resource the pages read, one query each. Mutations invalidate
// these keys and WebSocket messages update them, so pages never fetch directly.
import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api"

export type Note = { id: number; text: string; author_email: string; mine: boolean; created_at: string }
export type KeyStatus = { set: boolean; last_four?: string; updated_at?: string }

export const notesKey = ["notes"] as const
export const emailKeyKey = ["email-key"] as const

export function useNotes(enabled: boolean) {
  return useQuery({ queryKey: notesKey, queryFn: () => api<Note[]>("/api/notes"), enabled })
}

export function useEmailKey(enabled: boolean) {
  return useQuery({ queryKey: emailKeyKey, queryFn: () => api<KeyStatus>("/api/email/key"), enabled })
}
