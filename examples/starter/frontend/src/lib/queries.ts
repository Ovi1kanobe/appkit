// Every server resource the pages read, one query each. Mutations invalidate
// these keys and WebSocket messages update them, so pages never fetch directly.
export {}
