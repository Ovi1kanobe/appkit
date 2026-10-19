import { ApiKeyList } from "@/components/ApiKeyList"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useSignedIn } from "@/lib/session"

export function Account() {
  const { user, keys } = useSignedIn()

  return (
    <div className="flex flex-col gap-6">
      <Card className="animate-in duration-200 ease-out fade-in">
        <CardHeader>
          <CardTitle>Account</CardTitle>
          <CardDescription>Who you are signed in as.</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Email</dt>
            <dd className="truncate" title={user.email}>
              {user.email ?? "None"}
            </dd>
            <dt className="text-muted-foreground">Subject</dt>
            <dd className="truncate font-mono" title={user.subject}>
              {user.subject}
            </dd>
          </dl>
        </CardContent>
      </Card>
      {/* The session carries keys only when this person may give a key at least one permission. */}
      {keys && <ApiKeyList options={keys} />}
    </div>
  )
}
