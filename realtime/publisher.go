package realtime

import (
	"context"
	"sync"

	"github.com/Ovi1kanobe/appkit/identity"
)

// Publisher sends each subscriber of a topic their own view of every change a
// system reports. Add never blocks the caller and keeps the latest change per
// key until Run sends it, so a burst of changes to one item is one message and
// no change is lost. Changes are sent in the order their keys first arrived.
// A subscriber whose write takes longer than five seconds is closed, and its
// page refetches when it reconnects, so one slow page never costs another a change.
//
// C is the system's own Change type and K is what identifies the changed item,
// so the system never imports this package: pass Add as its onChange.
type Publisher[K comparable, C any] struct {
	hub     *Hub
	topic   string
	key     func(C) K
	view    func(context.Context, C) func(identity.Identity) ([]byte, bool)
	mutex   sync.Mutex
	merge   func(previous, next C) C
	pending map[K]C
	order   []K
	signal  chan struct{}
}

// NewPublisher makes a publisher for topic. key says which item a change is
// about. view runs once per change sent and returns what each subscriber
// receives for it, or false to send that person nothing; work shared by every
// subscriber, such as a lookup, belongs in view itself, and work that depends
// on the person in the function it returns. A nil function sends nothing.
func NewPublisher[K comparable, C any](hub *Hub, topic string, key func(C) K, view func(ctx context.Context, change C) func(person identity.Identity) ([]byte, bool)) *Publisher[K, C] {
	return &Publisher[K, C]{hub: hub, topic: topic, key: key, view: view, pending: map[K]C{}, signal: make(chan struct{}, 1)}
}

// Merge sets how a pending change and a newer one for the same key combine;
// without it the newer change replaces the pending one.
func (publisher *Publisher[K, C]) Merge(merge func(previous, next C) C) {
	publisher.mutex.Lock()
	publisher.merge = merge
	publisher.mutex.Unlock()
}

// Add keeps change until Run sends it. It never blocks.
func (publisher *Publisher[K, C]) Add(change C) {
	key := publisher.key(change)
	publisher.mutex.Lock()
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

// Run sends pending changes until ctx ends. Changes added after it returns
// are kept but never sent.
func (publisher *Publisher[K, C]) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-publisher.signal:
			publisher.mutex.Lock()
			pending, order := publisher.pending, publisher.order
			publisher.pending, publisher.order = map[K]C{}, nil
			publisher.mutex.Unlock()
			for _, key := range order {
				if view := publisher.view(ctx, pending[key]); view != nil {
					_ = publisher.hub.PublishEach(ctx, publisher.topic, view)
				}
			}
		}
	}
}
