// The only way the frontend calls the backend: same-origin JSON with {"error"} bodies.
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function api<Result>(path: string, options: { method?: string; body?: unknown } = {}): Promise<Result> {
  const method = options.method ?? "GET"
  // Every POST creates, so each carries a fresh request_id and the server answers a repeat with the first record.
  const body =
    method === "POST" ? { ...(options.body as object | undefined), request_id: crypto.randomUUID() } : options.body
  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    })
  } catch {
    // fetch rejects only when no response arrives, such as when the server is down or the network drops.
    throw new ApiError(0, "The server cannot be reached.")
  }
  if (response.status === 401) {
    window.location.assign(`/auth/login?next=${encodeURIComponent(window.location.pathname)}`)
    throw new ApiError(401, "Signed out")
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string }
    throw new ApiError(response.status, body.error ?? "Something went wrong")
  }
  return (response.status === 204 ? undefined : await response.json()) as Result
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong"
}
