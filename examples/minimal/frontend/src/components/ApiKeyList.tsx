import { useMutation, useQueryClient } from "@tanstack/react-query"
import { cn } from "cn"
import { useState } from "react"
import { toast } from "sonner"

import { NewKeyDialog } from "@/components/NewKeyDialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { api, errorMessage } from "@/lib/api"
import { type ApiKey, apiKeysKey, useApiKeys } from "@/lib/queries"
import type { KeyOptions } from "@/lib/session"

// The first row has no top padding, so the list starts level with the card's content.
const keyRowClassName = "flex items-start gap-3 py-3 first:pt-0"

// The list area always holds at least three one-line rows (68px each, 12px padding, 1px dividers),
// so loading, empty, error, and short lists take the same space.
const listAreaClassName = "min-h-[254px]"

function formatTime(time: string) {
  return new Date(time).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
}

// A key's permissions shrink when the person loses a group, so a key never outgrows its owner.
function isNarrowed(key: ApiKey) {
  return key.scopes.some((scope) => !key.permissions.includes(scope))
}

export function ApiKeyList({ options }: { options: KeyOptions }) {
  const queryClient = useQueryClient()
  const keys = useApiKeys(true)
  // The key stays set while the confirm fades out, so its name does not vanish mid-fade.
  const [revoking, setRevoking] = useState<ApiKey>()
  const [confirmOpen, setConfirmOpen] = useState(false)

  const revoke = useMutation({
    mutationFn: (id: string) => api(`/auth/keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: apiKeysKey }),
    onError: (error) => toast.error(errorMessage(error)),
  })

  const now = Date.now()

  return (
    <Card className="animate-in duration-200 ease-out fade-in">
      <CardHeader>
        <CardTitle>API keys</CardTitle>
        <CardDescription>Let scripts and tools act as you, with only the permissions you give them.</CardDescription>
        <CardAction>
          <NewKeyDialog options={options} />
        </CardAction>
      </CardHeader>
      <CardContent className={listAreaClassName}>
        {keys.isPending ? (
          <ul className="divide-y">
            {[0, 1, 2].map((row) => (
              <li key={row} className={keyRowClassName}>
                <div className="flex flex-1 flex-col gap-1.5">
                  <div className="flex h-5 items-center">
                    <Skeleton className="h-3.5 w-1/3" />
                  </div>
                  <Skeleton className="h-5 w-1/2" />
                  <div className="flex h-4 items-center">
                    <Skeleton className="h-3 w-2/3" />
                  </div>
                </div>
              </li>
            ))}
          </ul>
        ) : keys.isError ? (
          <div className="flex items-center justify-between gap-3 text-sm">
            <p className="text-destructive">{errorMessage(keys.error)}</p>
            <Button variant="outline" size="sm" onClick={() => void keys.refetch()}>
              Retry
            </Button>
          </div>
        ) : keys.data.length ? (
          <ul className="divide-y">
            {keys.data.map((key) => {
              const expired = !key.revoked_at && new Date(key.expires_at).getTime() <= now
              const live = !key.revoked_at && !expired
              return (
                <li key={key.id} className={keyRowClassName}>
                  <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                    <div className="flex h-5 min-w-0 items-center gap-2">
                      <p className="truncate text-sm font-medium" title={key.name}>
                        {key.name}
                      </p>
                      <span className="shrink-0 font-mono text-xs text-muted-foreground">{key.id}</span>
                      {!live && <Badge variant="secondary">{key.revoked_at ? "Revoked" : "Expired"}</Badge>}
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {key.scopes.map((scope) => (
                        <Badge
                          key={scope}
                          variant="outline"
                          className={cn(
                            live && !key.permissions.includes(scope) && "text-muted-foreground line-through",
                          )}
                        >
                          {scope}
                        </Badge>
                      ))}
                    </div>
                    {live && isNarrowed(key) && (
                      <p className="text-xs text-muted-foreground">
                        {key.permissions.length
                          ? `Now gets only ${key.permissions.join(", ")}, since you no longer hold the rest.`
                          : "Gets nothing now, since you no longer hold these permissions."}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Created {formatTime(key.created_at)} ·{" "}
                      {key.revoked_at
                        ? `Revoked ${formatTime(key.revoked_at)}`
                        : `${expired ? "Expired" : "Expires"} ${formatTime(key.expires_at)}`}{" "}
                      · {key.last_used_at ? `Last used ${formatTime(key.last_used_at)}` : "Never used"}
                    </p>
                  </div>
                  {live && (
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`Revoke ${key.name}`}
                      onClick={() => {
                        setRevoking(key)
                        setConfirmOpen(true)
                      }}
                    >
                      Revoke
                    </Button>
                  )}
                </li>
              )
            })}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No keys yet.</p>
        )}
      </CardContent>
      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke {revoking?.name}?</AlertDialogTitle>
            <AlertDialogDescription>Anything using this key stops working at once.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => revoking && revoke.mutate(revoking.id)}>
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
