package identity

import "time"

// SetRouterClock makes the rate limits mounted on router from now on read the
// time from now, so tests advance it instead of sleeping.
func SetRouterClock(router *Router, now func() time.Time) { router.now = now }
