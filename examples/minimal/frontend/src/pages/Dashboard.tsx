import { useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useSignedIn } from "@/lib/session"
import { useSocket } from "@/lib/socket"

type Status = { uptime_seconds: number }

export function Dashboard() {
  const { can } = useSignedIn()
  const allowed = can("diagnostics.read")
  const [status, setStatus] = useState<Status>()
  const connection = useSocket(allowed ? "/ws/status" : null, (data) => setStatus(JSON.parse(data) as Status))

  return (
    <Card className="animate-in duration-200 ease-out fade-in">
      <CardHeader>
        <CardTitle>Diagnostics</CardTitle>
        <CardDescription>Live process status over a session-authenticated WebSocket.</CardDescription>
      </CardHeader>
      <CardContent>
        {allowed ? (
          <div className="flex items-center justify-between">
            {status ? (
              <p className="text-2xl font-semibold tabular-nums">{status.uptime_seconds}s uptime</p>
            ) : (
              <div className="flex h-8 items-center">
                <Skeleton className="h-6 w-40" />
              </div>
            )}
            <Badge variant={connection === "live" ? "default" : "secondary"}>{connection}</Badge>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">You need the diagnostics.read permission.</p>
        )}
      </CardContent>
    </Card>
  )
}
