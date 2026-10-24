package identity

import "time"

// SetRouterClock makes the rate limits mounted on router from now on read the
// time from now, so tests advance it instead of sleeping.
func SetRouterClock(router *Router, now func() time.Time) { router.now = now }

// SetRouterRateLimitKeys makes the rate limits mounted on router from now on
// track at most keys callers, and returns the previous cap, so a test fills a
// table without a hundred thousand requests.
func SetRouterRateLimitKeys(router *Router, keys int) (previous int) {
	previous, router.rateLimitKeys = router.rateLimitKeys, keys
	return previous
}
