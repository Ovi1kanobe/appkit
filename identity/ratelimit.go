package identity

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimit caps how often one caller may call a route: Requests at once,
// refilled continuously at Requests per Per. A public route counts per client
// address, as RouterConfig.ClientAddress reads it; a private or service route
// counts per identity subject, so a person's session and keys share one
// bucket and an application has its own under its client ID. The zero value
// means no limit; a value with only one field set, or a negative one, panics
// at mount.
type RateLimit struct {
	Requests int
	Per      time.Duration
}

// rateLimitSweepAt is the number of keys at which an insert sweeps idle
// ones even when no timed sweep is due.
const rateLimitSweepAt = 4096

// checkRateLimit panics unless limit is the zero value or has both fields
// above zero.
func checkRateLimit(kind, pattern string, limit RateLimit) {
	if limit.Requests < 0 || limit.Per < 0 || (limit.Requests == 0) != (limit.Per == 0) {
		panic(fmt.Sprintf("identity: router.%s(%q): a RateLimit needs both Requests and Per above zero, such as identity.RateLimit{Requests: 60, Per: time.Minute}, or neither for no limit", kind, pattern))
	}
}

// label describes limit for the mount log, such as "60/1m0s", or "" for no
// limit.
func (limit RateLimit) label() string {
	if limit == (RateLimit{}) {
		return ""
	}
	return fmt.Sprintf("%d/%s", limit.Requests, limit.Per)
}

// rateLimited wraps next in limit's token buckets, one per key that key
// returns for a request, or returns next unchanged for no limit. A request
// over the limit answers 429 with Retry-After and reaches nothing further.
func rateLimited(limit RateLimit, now func() time.Time, key func(*http.Request) string, next http.Handler) http.Handler {
	if limit == (RateLimit{}) {
		return next
	}
	limiter := &rateLimiter{limit: limit, now: now, buckets: map[string]*rateBucket{}, sweepAt: rateLimitSweepAt}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if wait, allowed := limiter.allow(key(request)); !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
			writeError(writer, http.StatusTooManyRequests, "Too many requests; try again later.")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// rateLimiter holds one route's token buckets, one per key, in memory. A key
// idle for Per has a full bucket, the same as none, so a sweep drops it; sweeps run on insert, when one is due or the map is large,
// so the map stays bounded without a background goroutine.
type rateLimiter struct {
	limit     RateLimit
	now       func() time.Time
	mu        sync.Mutex
	buckets   map[string]*rateBucket
	nextSweep time.Time
	sweepAt   int
}

// rateBucket is one key's tokens as of updated.
type rateBucket struct {
	tokens  float64
	updated time.Time
}

// allow takes a token from key's bucket. When the bucket is empty it returns
// false and how long until the next token.
func (limiter *rateLimiter) allow(key string) (wait time.Duration, allowed bool) {
	capacity := float64(limiter.limit.Requests)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	bucket, found := limiter.buckets[key]
	if !found {
		limiter.sweep(now)
		bucket = &rateBucket{tokens: capacity, updated: now}
		limiter.buckets[key] = bucket
	}
	// A full Per refills exactly, so no rounding leaves a refilled bucket short.
	elapsed := now.Sub(bucket.updated)
	switch {
	case elapsed >= limiter.limit.Per:
		bucket.tokens = capacity
	case elapsed > 0:
		bucket.tokens = min(capacity, bucket.tokens+float64(elapsed)*capacity/float64(limiter.limit.Per))
	}
	if elapsed > 0 {
		bucket.updated = now
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return 0, true
	}
	return time.Duration((1 - bucket.tokens) * float64(limiter.limit.Per) / capacity), false
}

// sweep drops every key idle for Per when a sweep is due or the map has
// reached sweepAt. A sweep that leaves the map large raises sweepAt to twice
// its size, so a map of live keys is not swept on every insert.
func (limiter *rateLimiter) sweep(now time.Time) {
	if now.Before(limiter.nextSweep) && len(limiter.buckets) < limiter.sweepAt {
		return
	}
	for key, bucket := range limiter.buckets {
		if now.Sub(bucket.updated) >= limiter.limit.Per {
			delete(limiter.buckets, key)
		}
	}
	limiter.nextSweep = now.Add(limiter.limit.Per)
	limiter.sweepAt = max(rateLimitSweepAt, 2*len(limiter.buckets))
}

// subjectKey keys a private or service route's buckets by the identity that
// require or bearer attached: a person's session and keys share one, and an
// application has its own under its client ID, which never collides with a
// person's subject.
func subjectKey(request *http.Request) string {
	actor, _ := FromContext(request.Context())
	if actor.Client {
		return "client:" + actor.Subject
	}
	return "person:" + actor.Subject
}
