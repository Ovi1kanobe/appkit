package identity

import (
	"container/list"
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

// rateLimitKeys is how many callers one route's rate limit tracks at most.
// When it is full, the caller seen least recently is dropped, so a flood of
// new addresses costs bounded memory and never refuses a new caller.
const rateLimitKeys = 100_000

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
func (router *Router) rateLimited(limit RateLimit, key func(*http.Request) string, next http.Handler) http.Handler {
	if limit == (RateLimit{}) {
		return next
	}
	limiter := &rateLimiter{limit: limit, now: router.now, maxKeys: router.rateLimitKeys, buckets: map[string]*list.Element{}, recent: list.New()}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if wait, allowed := limiter.allow(key(request)); !allowed {
			writer.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
			writeError(writer, http.StatusTooManyRequests, "Too many requests; try again later.")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// rateLimiter holds one route's token buckets, one per key, in memory, at
// most maxKeys of them. recent orders the buckets from the most recently used
// at the front to the least at the back. A key idle for Per has a full bucket,
// the same as none, so each insert first drops idle keys from the back, then
// the least recently used one when the table is still full. Both are O(1) per
// key dropped, with no background goroutine.
type rateLimiter struct {
	limit   RateLimit
	now     func() time.Time
	maxKeys int
	mu      sync.Mutex
	buckets map[string]*list.Element // each holds a *rateBucket
	recent  *list.List
}

// rateBucket is one key's tokens as of updated, the last time it was used.
type rateBucket struct {
	key     string
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
	element, found := limiter.buckets[key]
	if found {
		limiter.recent.MoveToFront(element)
	} else {
		limiter.evict(now)
		element = limiter.recent.PushFront(&rateBucket{key: key, tokens: capacity, updated: now})
		limiter.buckets[key] = element
	}
	bucket := element.Value.(*rateBucket)
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

// evict makes room for one more key: it drops every key idle for Per from
// the back of recent, then, while the table is still full, the least recently
// used key.
func (limiter *rateLimiter) evict(now time.Time) {
	for back := limiter.recent.Back(); back != nil; back = limiter.recent.Back() {
		bucket := back.Value.(*rateBucket)
		if now.Sub(bucket.updated) < limiter.limit.Per && len(limiter.buckets) < limiter.maxKeys {
			return
		}
		limiter.recent.Remove(back)
		delete(limiter.buckets, bucket.key)
	}
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
