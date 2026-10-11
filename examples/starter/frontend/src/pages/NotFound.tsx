import { Link } from "react-router"

export function NotFound() {
  return (
    <p className="text-sm text-muted-foreground">
      This page does not exist.{" "}
      <Link to="/" className="underline">
        Go home
      </Link>
    </p>
  )
}
