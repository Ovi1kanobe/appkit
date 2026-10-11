import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { api, errorMessage } from "@/lib/api"
import { emailKeyKey, type KeyStatus, useEmailKey } from "@/lib/queries"
import { useSignedIn } from "@/lib/session"
import { useSocket } from "@/lib/socket"

const keySchema = z.object({ api_key: z.string().trim().min(1, "Enter the API key.") })

const apiKeyErrorId = "api-key-error"

export function Settings() {
  const { can } = useSignedIn()
  const allowed = can("email.write")
  const queryClient = useQueryClient()
  const status = useEmailKey(allowed)
  const form = useForm({ resolver: zodResolver(keySchema), defaultValues: { api_key: "" } })

  // Another admin's change arrives as the new status.
  useSocket(
    allowed ? "/ws/email" : null,
    (data) => queryClient.setQueryData(emailKeyKey, JSON.parse(data) as KeyStatus),
    () => queryClient.invalidateQueries({ queryKey: emailKeyKey }),
  )

  const save = useMutation({
    mutationFn: (values: z.infer<typeof keySchema>) => api("/api/email/key", { method: "PUT", body: values }),
    onSuccess: () => {
      form.reset()
      return queryClient.invalidateQueries({ queryKey: emailKeyKey })
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const keySummary =
    status.data?.set && status.data.updated_at
      ? `Ends in ${status.data.last_four} · updated ${new Date(status.data.updated_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}`
      : undefined

  if (!allowed) return <p className="text-sm text-muted-foreground">You need the email.write permission.</p>

  return (
    // The bottom padding holds the API key error, so showing it moves nothing.
    <Card className="animate-in pb-7 duration-200 ease-out fade-in">
      <CardHeader>
        <CardTitle>Email provider</CardTitle>
        <CardDescription>The API key is stored encrypted and never shown again.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex h-6 items-center gap-3 text-sm">
          {status.data ? (
            <>
              <Badge variant={status.data.set ? "default" : "secondary"}>{status.data.set ? "Set" : "Not set"}</Badge>
              {keySummary && (
                // One line keeps the status row's height; the full text stays available on hover.
                <span className="min-w-0 truncate text-muted-foreground" title={keySummary}>
                  {keySummary}
                </span>
              )}
            </>
          ) : status.isError ? (
            <>
              <span className="text-destructive">{errorMessage(status.error)}</span>
              <Button variant="outline" size="sm" onClick={() => void status.refetch()}>
                Retry
              </Button>
            </>
          ) : (
            <Skeleton className="h-5 w-48" />
          )}
        </div>
        <form onSubmit={form.handleSubmit((values) => save.mutate(values))}>
          <Controller
            name="api_key"
            control={form.control}
            render={({ field, fieldState }) => (
              <Field data-invalid={fieldState.invalid} className="relative">
                <div className="flex gap-2">
                  <Input
                    {...field}
                    type="password"
                    autoComplete="off"
                    placeholder={status.data?.set ? "Replace API key" : "API key"}
                    aria-label="API key"
                    aria-invalid={fieldState.invalid}
                    aria-describedby={fieldState.invalid ? apiKeyErrorId : undefined}
                  />
                  <Button type="submit" disabled={save.isPending}>
                    Save
                  </Button>
                </div>
                <FieldError id={apiKeyErrorId} errors={[fieldState.error]} className="absolute top-full mt-1" />
              </Field>
            )}
          />
        </form>
      </CardContent>
    </Card>
  )
}
