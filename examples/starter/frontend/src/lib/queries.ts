// Every server resource the pages read, one query each. Mutations invalidate
// these keys and WebSocket messages update them, so pages never fetch directly.
import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api"

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

export const apiKeysKey = ["keys"] as const

export function useApiKeys(enabled: boolean) {
  return useQuery({
    queryKey: apiKeysKey,
    queryFn: async () => (await api<{ keys: ApiKey[] }>("/auth/keys")).keys,
    enabled,
  })
}
