package realtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/coder/websocket"
)

// withSubject gives the request the identity its ?subject names, as sessions would.
func withSubject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		subject := request.URL.Query().Get("subject")
		if subject != "" {
			request = request.WithContext(identity.WithContext(request.Context(), identity.Identity{Subject: subject}))
		}
		next.ServeHTTP(writer, request)
	})
}

func dial(t *testing.T, ctx context.Context, server *httptest.Server, subject string) *websocket.Conn {
	t.Helper()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"?subject="+subject, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseNow() })
	return client
}

func readText(t *testing.T, ctx context.Context, client *websocket.Conn) string {
	t.Helper()
	_, data, err := client.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestConnectionLifecycle(t *testing.T) {
	var hub Hub
	defer hub.Close()
	accepted := make(chan *Conn, 3)
	finished := make(chan struct{}, 3)
	server := httptest.NewServer(withSubject(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := hub.Accept(writer, request)
		if err != nil {
			return
		}
		defer connection.Close()
		defer func() { finished <- struct{}{} }()
		if err := connection.Subscribe("updates"); err != nil {
			t.Error(err)
		}
		accepted <- connection
		connection.Keep(request.Context())
	})))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, firstServer := dial(t, ctx, server, "same"), <-accepted
	second, secondServer := dial(t, ctx, server, "same"), <-accepted
	third, thirdServer := dial(t, ctx, server, "other"), <-accepted
	if firstServer.Identity().Subject != "same" {
		t.Fatal("identity lost")
	}
	// PublishEach sends each person only what view returns for them.
	if err := hub.PublishEach(ctx, "updates", func(person identity.Identity) ([]byte, bool) {
		return []byte("only " + person.Subject), person.Subject == "same"
	}); err != nil {
		t.Fatal(err)
	}
	for _, client := range []*websocket.Conn{first, second} {
		if data := readText(t, ctx, client); data != "only same" {
			t.Fatalf("view message=%q", data)
		}
	}
	if err := thirdServer.Write(ctx, []byte("next")); err != nil {
		t.Fatal(err)
	}
	if data := readText(t, ctx, third); data != "next" {
		t.Fatalf("skipped subscriber received %q", data)
	}
	if err := firstServer.Subscribe(""); err == nil {
		t.Fatal("empty topic accepted")
	}
	firstServer.Close()
	secondServer.Close()
	for _, connection := range []*Conn{firstServer, secondServer} {
		if !errors.Is(connection.Subscribe("updates"), ErrClosed) {
			t.Fatal("closed connection retained")
		}
	}
	if err := thirdServer.Write(ctx, []byte("still open")); err != nil {
		t.Fatal(err)
	}
	if data := readText(t, ctx, third); data != "still open" {
		t.Fatal("wrong connection closed")
	}
	_ = third.CloseNow()
	for range 3 {
		select {
		case <-finished:
		case <-ctx.Done():
			t.Fatal("read cleanup did not finish")
		}
	}
	hub.mu.Lock()
	remaining := len(hub.connections)
	hub.mu.Unlock()
	if remaining != 0 {
		t.Fatal("connections leaked")
	}
	hub.Close()
	hub.Close()
}

func TestAuthenticationAndOrigin(t *testing.T) {
	for _, test := range []struct {
		name, subject, origin string
		closed                bool
		status                int
	}{{"anonymous", "", "", false, 401}, {"cross origin", "one", "https://attacker.example", false, 403}, {"closed hub", "one", "", true, 503}} {
		t.Run(test.name, func(t *testing.T) {
			var hub Hub
			defer hub.Close()
			if test.closed {
				hub.Close()
			}
			server := httptest.NewServer(withSubject(hub.Subscriber("updates")))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			headers := http.Header{}
			if test.origin != "" {
				headers.Set("Origin", test.origin)
			}
			client, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"?subject="+test.subject, &websocket.DialOptions{HTTPHeader: headers})
			if client != nil {
				_ = client.CloseNow()
			}
			if err == nil || response == nil || response.StatusCode != test.status {
				t.Fatalf("response=%v err=%v", response, err)
			}
		})
	}
}

func TestConcurrentWritesAndPing(t *testing.T) {
	var hub Hub
	defer hub.Close()
	accepted := make(chan *Conn, 1)
	server := httptest.NewServer(withSubject(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := hub.Accept(writer, request)
		if err != nil {
			return
		}
		defer connection.Close()
		accepted <- connection
		connection.Keep(request.Context())
	})))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := dial(t, ctx, server, "one")
	connection := <-accepted
	var writers sync.WaitGroup
	for range 10 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			if err := connection.Write(ctx, []byte("message")); err != nil {
				t.Error(err)
			}
		}()
	}
	for range 10 {
		readText(t, ctx, client)
	}
	writers.Wait()
	readContext := client.CloseRead(ctx)
	if err := connection.ping(readContext); err != nil {
		t.Fatal(err)
	}
	hub.Close()
	if !errors.Is(connection.Subscribe("late"), ErrClosed) {
		t.Fatal("shutdown retained connection")
	}
}

type change struct {
	ID    int
	Text  string
	Owner string
}

func TestPublisher(t *testing.T) {
	var hub Hub
	defer hub.Close()
	server := httptest.NewServer(withSubject(hub.Subscriber("items.changed")))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var prepared atomic.Int32 // view runs once per change sent
	var viewed sync.Map       // subject -> how many changes the returned function saw
	publisher := NewPublisher(&hub, "items.changed",
		func(item change) int { return item.ID },
		func(_ context.Context, item change) func(identity.Identity) ([]byte, bool) {
			prepared.Add(1)
			message := []byte(strconv.Itoa(item.ID) + ":" + item.Text)
			return func(person identity.Identity) ([]byte, bool) {
				count, _ := viewed.LoadOrStore(person.Subject, new(int))
				*count.(*int)++
				return message, item.Owner == person.Subject
			}
		})
	publisher.Merge(func(previous, next change) change {
		next.Text = previous.Text + "+" + next.Text
		return next
	})
	owner := dial(t, ctx, server, "owner")
	other := dial(t, ctx, server, "other")
	// Added before Run: the latest per item is kept, merged, in first-arrival order.
	publisher.Add(change{ID: 1, Text: "a", Owner: "owner"})
	publisher.Add(change{ID: 2, Text: "b", Owner: "owner"})
	publisher.Add(change{ID: 3, Text: "c", Owner: "other"})
	publisher.Add(change{ID: 2, Text: "d", Owner: "owner"})
	runContext, stop := context.WithCancel(ctx)
	stopped := make(chan struct{})
	go func() { publisher.Run(runContext); close(stopped) }()
	for _, expected := range []string{"1:a", "2:b+d"} {
		if data := readText(t, ctx, owner); data != expected {
			t.Fatalf("owner received %q, expected %q", data, expected)
		}
	}
	if data := readText(t, ctx, other); data != "3:c" {
		t.Fatalf("other received %q", data)
	}
	// A change added while Run waits is sent too.
	publisher.Add(change{ID: 1, Text: "e", Owner: "other"})
	if data := readText(t, ctx, other); data != "1:e" {
		t.Fatalf("other received %q", data)
	}
	if prepared.Load() != 4 {
		t.Fatalf("view ran %d times, expected once per change sent", prepared.Load())
	}
	for _, subject := range []string{"owner", "other"} {
		count, _ := viewed.Load(subject)
		if *count.(*int) != 4 {
			t.Fatalf("%s viewed %d changes, expected 4", subject, *count.(*int))
		}
	}
	stop()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("Run did not stop")
	}
	// After Run, Add drops the change instead of keeping it forever.
	publisher.Add(change{ID: 9, Text: "late", Owner: "owner"})
	publisher.mutex.Lock()
	kept := len(publisher.pending)
	publisher.mutex.Unlock()
	if kept != 0 {
		t.Fatalf("kept %d changes after Run returned", kept)
	}
}

func TestIdentityIsACopy(t *testing.T) {
	connection := &Conn{actor: identity.Identity{Subject: "one", Groups: []string{"g"}, Roles: []string{"r"}, Permissions: []string{"notes.read"}}}
	copied := connection.Identity()
	copied.Groups[0], copied.Roles[0], copied.Permissions[0] = "x", "x", "x"
	if connection.actor.Groups[0] != "g" || connection.actor.Roles[0] != "r" || !connection.actor.Can("notes.read") {
		t.Fatal("Identity shared a slice with the connection")
	}
}
