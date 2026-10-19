import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Check, Copy, Plus } from "lucide-react"
import { useState } from "react"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Field, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { api, errorMessage } from "@/lib/api"
import { type ApiKey, apiKeysKey } from "@/lib/queries"
import type { KeyOptions } from "@/lib/session"

const day = 24 * 60 * 60

const keySchema = z.object({
  name: z.string().trim().min(1, "Name the key.").max(64, "Keep it to 64 characters."),
  scopes: z.array(z.string()).min(1, "Choose at least one permission."),
  lifetime: z.string(),
})

const nameErrorId = "key-name-error"
const scopesErrorId = "key-scopes-error"

// 7, 30, and 90 days where the app allows them, then the longest it allows, so there is always a choice.
function lifetimeChoices(maxSeconds: number) {
  return [...[7 * day, 30 * day, 90 * day].filter((seconds) => seconds < maxSeconds), maxSeconds]
}

function lifetimeLabel(seconds: number) {
  const [count, unit] =
    seconds % day === 0
      ? [seconds / day, "day"]
      : seconds % 3600 === 0
        ? [seconds / 3600, "hour"]
        : [Math.max(1, Math.round(seconds / 60)), "minute"]
  return `${count} ${unit}${count === 1 ? "" : "s"}`
}

export function NewKeyDialog({ options }: { options: KeyOptions }) {
  const queryClient = useQueryClient()
  const lifetimes = lifetimeChoices(options.max_lifetime_seconds)
  const defaults = {
    name: "",
    scopes: [],
    lifetime: String(lifetimes.includes(30 * day) ? 30 * day : lifetimes[lifetimes.length - 1]),
  }
  const form = useForm({ resolver: zodResolver(keySchema), defaultValues: defaults })
  // The secret lives only here, from the moment the key is made until the dialog closes.
  const [secret, setSecret] = useState<string>()
  const [copied, setCopied] = useState(false)

  const create = useMutation({
    mutationFn: (values: z.infer<typeof keySchema>) =>
      api<{ key: ApiKey; secret: string }>("/auth/keys", {
        method: "POST",
        body: { name: values.name, scopes: values.scopes, lifetime_seconds: Number(values.lifetime) },
      }),
    onSuccess: (result) => {
      setSecret(result.secret)
      return queryClient.invalidateQueries({ queryKey: apiKeysKey })
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  function copySecret() {
    if (!secret) return
    navigator.clipboard.writeText(secret).then(
      () => setCopied(true),
      () => toast.error("The key could not be copied."),
    )
  }

  // Cleared once the dialog has faded out, so it never swaps content while closing.
  function clear() {
    setSecret(undefined)
    setCopied(false)
    form.reset(defaults)
    create.reset()
  }

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus />
          New key
        </Button>
      </DialogTrigger>
      <DialogContent
        onCloseAutoFocus={clear}
        // A click outside or Escape would lose the secret, so only Done or Close end that view.
        onInteractOutside={(event) => secret && event.preventDefault()}
        onEscapeKeyDown={(event) => secret && event.preventDefault()}
      >
        {secret ? (
          <>
            <DialogHeader>
              <DialogTitle>Copy your key</DialogTitle>
              <DialogDescription>It will not be shown again.</DialogDescription>
            </DialogHeader>
            <div className="flex gap-2">
              <Input
                readOnly
                value={secret}
                aria-label="API key"
                className="font-mono"
                onFocus={(event) => event.currentTarget.select()}
              />
              <Button variant="outline" size="icon" aria-label={copied ? "Copied" : "Copy key"} onClick={copySecret}>
                {copied ? <Check /> : <Copy />}
              </Button>
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button>Done</Button>
              </DialogClose>
            </DialogFooter>
          </>
        ) : (
          <form className="grid gap-4" onSubmit={form.handleSubmit((values) => create.mutate(values))}>
            <DialogHeader>
              <DialogTitle>New key</DialogTitle>
              <DialogDescription>A key acts as you, with only the permissions you give it.</DialogDescription>
            </DialogHeader>
            {/* Each error sits in the gap below its field, so showing it moves nothing. */}
            <FieldGroup className="gap-7 pb-3">
              <Controller
                name="name"
                control={form.control}
                render={({ field, fieldState }) => (
                  <Field data-invalid={fieldState.invalid} className="relative">
                    <FieldLabel htmlFor="key-name">Name</FieldLabel>
                    <Input
                      {...field}
                      id="key-name"
                      autoComplete="off"
                      placeholder="Deploy script"
                      maxLength={64}
                      aria-invalid={fieldState.invalid}
                      aria-describedby={fieldState.invalid ? nameErrorId : undefined}
                    />
                    <FieldError id={nameErrorId} errors={[fieldState.error]} className="absolute top-full mt-1" />
                  </Field>
                )}
              />
              <Controller
                name="scopes"
                control={form.control}
                render={({ field, fieldState }) => (
                  <FieldSet
                    data-invalid={fieldState.invalid}
                    className="relative gap-3"
                    aria-describedby={fieldState.invalid ? scopesErrorId : undefined}
                  >
                    <FieldLegend variant="label">Permissions</FieldLegend>
                    <div className="flex max-h-48 flex-col gap-3 overflow-y-auto">
                      {options.delegable.map((permission) => (
                        <Field key={permission} orientation="horizontal">
                          <Checkbox
                            id={`key-scope-${permission}`}
                            checked={field.value.includes(permission)}
                            aria-invalid={fieldState.invalid}
                            onCheckedChange={(checked) =>
                              field.onChange(
                                checked
                                  ? [...field.value, permission]
                                  : field.value.filter((scope) => scope !== permission),
                              )
                            }
                          />
                          <FieldLabel htmlFor={`key-scope-${permission}`} className="font-normal">
                            {permission}
                          </FieldLabel>
                        </Field>
                      ))}
                    </div>
                    <FieldError id={scopesErrorId} errors={[fieldState.error]} className="absolute top-full mt-1" />
                  </FieldSet>
                )}
              />
              <Controller
                name="lifetime"
                control={form.control}
                render={({ field }) => (
                  <Field>
                    <FieldLabel htmlFor="key-lifetime">Expires after</FieldLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger id="key-lifetime" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {lifetimes.map((seconds) => (
                          <SelectItem key={seconds} value={String(seconds)}>
                            {lifetimeLabel(seconds)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>
                )}
              />
            </FieldGroup>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button type="submit" disabled={create.isPending}>
                Create
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
