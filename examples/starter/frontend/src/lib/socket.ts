// One live WebSocket per page. Close code 4401 means the session ended, so it
// refreshes sign-in state instead of reconnecting; any other close reconnects,
// waiting twice as long after each failure up to a limit. onConnect runs each
// time the socket opens, so the page refetches what it missed while offline.
import { useEffect, useRef, useState } from "react"

import { refreshSession } from "@/lib/session"

const sessionEnded = 4401
const firstReconnectDelay = 1000
const longestReconnectDelay = 30_000

export type SocketStatus = "connecting" | "live" | "disconnected"

export function useSocket(
  path: string | null,
  onMessage: (data: string) => void,
  onConnect?: () => void,
): SocketStatus {
  const [status, setStatus] = useState<SocketStatus>("connecting")
  const handler = useRef(onMessage)
  handler.current = onMessage
  const connected = useRef(onConnect)
  connected.current = onConnect

  useEffect(() => {
    if (!path) return
    let socket: WebSocket | undefined
    let retry: number | undefined
    let stopped = false
    let reconnectDelay = firstReconnectDelay
    const connect = () => {
      const url = new URL(path, window.location.href)
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:"
      socket = new WebSocket(url)
      socket.onopen = () => {
        reconnectDelay = firstReconnectDelay
        setStatus("live")
        connected.current?.()
      }
      socket.onmessage = (event) => handler.current(String(event.data))
      socket.onclose = (event) => {
        setStatus("disconnected")
        if (stopped) return
        if (event.code === sessionEnded) void refreshSession()
        else {
          retry = window.setTimeout(connect, reconnectDelay)
          reconnectDelay = Math.min(reconnectDelay * 2, longestReconnectDelay)
        }
      }
    }
    connect()
    return () => {
      stopped = true
      window.clearTimeout(retry)
      socket?.close()
    }
  }, [path])

  return status
}
