package realtime

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// retryAfter is how long Run waits before trying again a change whose view failed.
const retryAfter = time.Second

// Publisher sends each subscriber of a topic their own view of every change a
// system reports. Add never blocks the caller and keeps the latest change per
// key until Run sends it, so a burst of changes to one item is one message and
// no change is lost. Changes are sent in the order their keys first arrived.
// A change whose view fails, such as on a database error, is kept and tried
// again after a second, unless a newer change for its key replaced it.
// A subscriber whose write takes longer than five seconds is closed, and its
// page refetches when it reconnects, so one slow page delays the others by at
// most that once and never costs them a change.
//
// C is the system's own Change type and K is what identifies the changed item,
// so the system never imports this package: pass Add as its onChange.
type Publisher[K comparable, C any] struct {
	hub     *Hub
	topic   string
	key     func(C) K
	view    func(context.Context, C) (View, error)
	mutex   sync.Mutex
	merge   func(previous, next C) C
	pending map[K]C
	order   []K
	signal  chan struct{}
	stopped bool
}

// NewPublisher makes a publisher for topic. key says which item a change is
// about. view runs once per change sent and returns the View each subscriber
// is asked through; work shared by every subscriber, such as a lookup, belongs
// in view itself, and work that depends on the person in the View. A nil View
// sends nothing; an error keeps the change to try again.
func NewPublisher[K comparable, C any](hub *Hub, topic string, key func(C) K, view func(ctx context.Context, change C) (View, error)) *Publisher[K, C] {
	return &Publisher[K, C]{hub: hub, topic: topic, key: key, view: view, pending: map[K]C{}, signal: make(chan struct{}, 1)}
}

// Merge sets how a pending change and a newer one for the same key combine;
// without it the newer change replaces the pending one.
func (publisher *Publisher[K, C]) Merge(merge func(previous, next C) C) {
	publisher.mutex.Lock()
	publisher.merge = merge
	publisher.mutex.Unlock()
}

// Add keeps change until Run sends it. It never blocks. After Run has
// returned the change is dropped, since nothing would ever send it.
func (publisher *Publisher[K, C]) Add(change C) {
	key := publisher.key(change)
	publisher.mutex.Lock()
	if publisher.stopped {
		publisher.mutex.Unlock()
		return
	}
	previous, pending := publisher.pending[key]
	if pending && publisher.merge != nil {
		change = publisher.merge(previous, change)
	}
	if !pending {
		publisher.order = append(publisher.order, key)
	}
	publisher.pending[key] = change
	publisher.mutex.Unlock()
	select {
	case publisher.signal <- struct{}{}:
	default:
	}
}

// Run sends pending changes until ctx ends, logging and retrying any whose
// view fails. Changes added after it returns are dropped.
func (publisher *Publisher[K, C]) Run(ctx context.Context) {
	defer func() {
		publisher.mutex.Lock()
		publisher.stopped = true
		publisher.pending, publisher.order = nil, nil
		publisher.mutex.Unlock()
	}()
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-publisher.signal:
		case <-retry:
		}
		publisher.mutex.Lock()
		pending, order := publisher.pending, publisher.order
		publisher.pending, publisher.order = map[K]C{}, nil
		publisher.mutex.Unlock()
		var failed []K
		for _, key := range order {
			view, err := publisher.view(ctx, pending[key])
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.ErrorContext(ctx, "realtime: publish", "topic", publisher.topic, "error", err)
				failed = append(failed, key)
				continue
			}
			if view != nil {
				_ = publisher.hub.PublishEach(ctx, publisher.topic, view)
			}
		}
		retry = nil
		if len(failed) > 0 {
			publisher.keep(failed, pending)
			retry = time.After(retryAfter)
		}
	}
}

// keep puts failed changes back ahead of those added since, merging each with
// a newer change for its key when Merge is set, and otherwise letting the
// newer change replace it.
func (publisher *Publisher[K, C]) keep(failed []K, changes map[K]C) {
	publisher.mutex.Lock()
	defer publisher.mutex.Unlock()
	order := make([]K, 0, len(failed)+len(publisher.order))
	first := map[K]bool{}
	for _, key := range failed {
		first[key] = true
		newer, replaced := publisher.pending[key]
		switch {
		case !replaced:
			publisher.pending[key] = changes[key]
		case publisher.merge != nil:
			publisher.pending[key] = publisher.merge(changes[key], newer)
		}
		order = append(order, key)
	}
	for _, key := range publisher.order {
		if !first[key] {
			order = append(order, key)
		}
	}
	publisher.order = order
}
