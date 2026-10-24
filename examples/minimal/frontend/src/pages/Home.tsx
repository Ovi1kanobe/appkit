import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { cn } from "cn"
import { Trash2 } from "lucide-react"
import { useRef } from "react"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldError } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { api, errorMessage } from "@/lib/api"
import { type Note, notesKey, useNotes } from "@/lib/queries"
import { useSignedIn } from "@/lib/session"
import { useSocket } from "@/lib/socket"

const noteSchema = z.object({
  text: z.string().trim().min(1, "Write a note first.").max(500, "Keep it under 500 characters."),
})

// The first row has no top padding, so the gap under the note input, which holds its error, sets the spacing.
const noteRowClassName = "flex items-start gap-3 py-3 first:pt-0"

// The list area always holds at least three one-line rows (36px each, 12px padding, 1px dividers),
// so loading, empty, error, and short lists take the same space.
const listAreaClassName = "min-h-[170px]"

const noteErrorId = "note-error"

export function Home() {
  const { can } = useSignedIn()
  const canRead = can("notes.read")
  const canWrite = can("notes.write")
  const queryClient = useQueryClient()
  const notes = useNotes(canRead)
  const form = useForm({ resolver: zodResolver(noteSchema), defaultValues: { text: "" } })
  // Notes from the first load appear with the page; only notes that arrive later fade and slide in.
  const firstLoadNoteIds = useRef<Set<number>>(null)
  if (notes.data && !firstLoadNoteIds.current) firstLoadNoteIds.current = new Set(notes.data.map((note) => note.id))

  // Each change arrives as the note this person sees, or its removal.
  useSocket(
    canRead ? "/ws/notes" : null,
    (data) => {
      const message = JSON.parse(data) as { note?: Note; id?: number; removed?: boolean }
      queryClient.setQueryData<Note[]>(notesKey, (current = []) => {
        const others = current.filter((existing) => existing.id !== (message.note?.id ?? message.id))
        return message.note ? [message.note, ...others].sort((a, b) => b.id - a.id) : others
      })
    },
    () => queryClient.invalidateQueries({ queryKey: notesKey }),
  )

  const create = useMutation({
    mutationFn: (values: z.infer<typeof noteSchema>) => api("/api/notes", { method: "POST", body: values }),
    onSuccess: () => {
      form.reset()
      return queryClient.invalidateQueries({ queryKey: notesKey })
    },
    onError: (error) => toast.error(errorMessage(error)),
  })
  const remove = useMutation({
    mutationFn: (id: number) => api(`/api/notes/${id}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: notesKey }),
    onError: (error) => toast.error(errorMessage(error)),
  })

  if (!canRead) return <p className="text-sm text-muted-foreground">You need the notes.read permission.</p>

  return (
    <Card className="animate-in duration-200 ease-out fade-in">
      <CardHeader>
        <CardTitle>Notes</CardTitle>
        <CardDescription>Shared with everyone who can read notes. Updates live.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-8">
        {canWrite && (
          <form onSubmit={form.handleSubmit((values) => create.mutate(values))}>
            <Controller
              name="text"
              control={form.control}
              render={({ field, fieldState }) => (
                <Field data-invalid={fieldState.invalid} className="relative">
                  <div className="flex gap-2">
                    <Input
                      {...field}
                      placeholder="Write a note"
                      aria-label="Note"
                      aria-invalid={fieldState.invalid}
                      aria-describedby={fieldState.invalid ? noteErrorId : undefined}
                      maxLength={500}
                    />
                    <Button type="submit" disabled={create.isPending}>
                      Add
                    </Button>
                  </div>
                  {/* The error sits in the gap below the input, so showing it moves nothing. */}
                  <FieldError id={noteErrorId} errors={[fieldState.error]} className="absolute top-full mt-1" />
                </Field>
              )}
            />
          </form>
        )}
        <div className={listAreaClassName}>
          {notes.isPending ? (
            <ul className="divide-y">
              {[0, 1, 2].map((row) => (
                <li key={row} className={noteRowClassName}>
                  <div className="flex flex-1 flex-col">
                    <div className="flex h-5 items-center">
                      <Skeleton className="h-3.5 w-3/4" />
                    </div>
                    <div className="flex h-4 items-center">
                      <Skeleton className="h-3 w-1/3" />
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          ) : notes.isError ? (
            <div className="flex items-center justify-between gap-3 text-sm">
              <p className="text-destructive">{errorMessage(notes.error)}</p>
              <Button variant="outline" size="sm" onClick={() => void notes.refetch()}>
                Retry
              </Button>
            </div>
          ) : notes.data.length ? (
            <ul className="divide-y">
              {notes.data.map((note) => (
                <li
                  key={note.id}
                  className={cn(
                    noteRowClassName,
                    !firstLoadNoteIds.current?.has(note.id) &&
                      "animate-in duration-200 ease-out fade-in slide-in-from-top-1",
                  )}
                >
                  <div className="min-w-0 flex-1">
                    <p className="break-words">{note.text}</p>
                    <p className="text-xs text-muted-foreground">
                      {/* A note a visitor posted through the public route has no author email. */}
                      {note.author_email || "Anonymous"} ·{" "}
                      {new Date(note.created_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
                    </p>
                  </div>
                  {note.mine && canWrite && (
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Delete note: ${note.text}`}
                      onClick={() => remove.mutate(note.id)}
                    >
                      <Trash2 />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No notes yet.</p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
