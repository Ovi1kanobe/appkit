package realtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/coder/websocket"
)

func TestConnectionLifecycle(t *testing.T) {
	var hub Hub
	defer hub.Close()
	accepted := make(chan *Conn, 3)
	finished := make(chan struct{}, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request = request.WithContext(identity.WithContext(request.Context(), identity.Identity{Subject: request.URL.Query().Get("subject")}))
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
		for {
			if _, err := connection.Read(request.Context()); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := func(subject string) (*websocket.Conn, *Conn) {
		t.Helper()
		client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"?subject="+subject, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.CloseNow() })
		select {
		case connection := <-accepted:
			return client, connection
		case <-ctx.Done():
			t.Fatal(ctx.Err())
			return nil, nil
		}
	}
	first, firstServer := dial("same")
	second, secondServer := dial("same")
	third, thirdServer := dial("other")
	if firstServer.Identity().Subject != "same" {
		t.Fatal("identity lost")
	}
	secondServer.Unsubscribe("updates")
	if err := hub.Publish(ctx, "updates", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	for _, client := range []*websocket.Conn{first, third} {
		_, data, err := client.Read(ctx)
		if err != nil || string(data) != "hello" {
			t.Fatalf("message=%q err=%v", data, err)
		}
	}
	// An unsubscribed client receives only this direct marker, not the publish.
	if err := secondServer.Write(ctx, []byte("marker")); err != nil {
		t.Fatal(err)
	}
	_, data, err := second.Read(ctx)
	if err != nil || string(data) != "marker" {
		t.Fatal("unsubscribe failed")
	}
	// PublishEach sends each person only what view returns for them.
	if err := hub.PublishEach(ctx, "updates", func(person identity.Identity) ([]byte, bool) {
		return []byte("only " + person.Subject), person.Subject == "same"
	}); err != nil {
		t.Fatal(err)
	}
	if _, data, err := first.Read(ctx); err != nil || string(data) != "only same" {
		t.Fatalf("view message=%q err=%v", data, err)
	}
	if err := thirdServer.Write(ctx, []byte("next")); err != nil {
		t.Fatal(err)
	}
	if _, data, err := third.Read(ctx); err != nil || string(data) != "next" {
		t.Fatalf("skipped subscriber received %q err=%v", data, err)
	}
	if err := firstServer.Subscribe(""); err == nil {
		t.Fatal("empty topic accepted")
	}
	hub.DisconnectSubject("same")
	for _, connection := range []*Conn{firstServer, secondServer} {
		if !errors.Is(connection.Subscribe("updates"), ErrClosed) {
			t.Fatal("closed connection retained")
		}
	}
	if err := thirdServer.Write(ctx, []byte("still open")); err != nil {
		t.Fatal(err)
	}
	_, data, err = third.Read(ctx)
	if err != nil || string(data) != "still open" {
		t.Fatal("wrong subject disconnected")
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.subject != "" {
					r = r.WithContext(identity.WithContext(r.Context(), identity.Identity{Subject: test.subject}))
				}
				connection, err := hub.Accept(w, r)
				if err == nil {
					connection.Close()
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			headers := http.Header{}
			if test.origin != "" {
				headers.Set("Origin", test.origin)
			}
			client, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{HTTPHeader: headers})
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(identity.WithContext(r.Context(), identity.Identity{Subject: "one"}))
		connection, err := hub.Accept(w, r)
		if err != nil {
			return
		}
		defer connection.Close()
		accepted <- connection
		for {
			if _, err := connection.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseNow()
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
		if _, _, err := client.Read(ctx); err != nil {
			t.Fatal(err)
		}
	}
	writers.Wait()
	readContext := client.CloseRead(ctx)
	if err := connection.Ping(readContext); err != nil {
		t.Fatal(err)
	}
	hub.Close()
	if !errors.Is(connection.Subscribe("late"), ErrClosed) {
		t.Fatal("shutdown retained connection")
	}
}
