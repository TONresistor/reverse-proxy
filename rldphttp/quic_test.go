package rldphttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

func startQUICGateway(t *testing.T) (*quic.Gateway, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newQUICGateway(key)
	if err != nil {
		t.Fatal(err)
	}
	return g, serveQUICGateway(t, g)
}

func serveQUICGateway(t *testing.T, g *quic.Gateway) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = g.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Serve(pc) }()
	t.Cleanup(func() {
		_ = g.Close()
		_ = pc.Close()
		if err := <-done; err != nil {
			t.Errorf("serve QUIC gateway: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	return pc.LocalAddr().String()
}

func TestQUICRequestObjectLimit(t *testing.T) {
	server, addr := startQUICGateway(t)
	var handled atomic.Int32
	server.SetConnectionHandler(func(peer *quic.Peer) error {
		c := newQUICClient(peer, 5*time.Second)
		c.SetOnQuery(func(_ []byte, query *rldp.Query) error {
			handled.Add(1)
			return c.SendAnswer(context.Background(), query.MaxAnswerSize, query.Timeout, query.ID, nil, Response{Version: "HTTP/1.1", StatusCode: 200, NoPayload: true})
		})
		return nil
	})
	// Keep the sender's larger default so rejection is enforced by the receiver.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := quic.NewGateway(key)
	if err != nil {
		t.Fatal(err)
	}
	serveQUICGateway(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer, err := client.DialDefault(ctx, server.PublicKey(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c := newQUICClient(peer, 5*time.Second)
	request := Request{ID: make([]byte, 32), Method: "GET", Version: "HTTP/1.1", URL: strings.Repeat("x", 2*((1<<21)-(1<<11))+1024)}
	var response Response
	if err := c.DoQuery(ctx, quic.DefaultMaxObjectSize, request, &response); err != nil {
		t.Fatalf("C++-sized request rejected: %v", err)
	}
	request.URL = strings.Repeat("x", quicMaxObjectSize)
	if err := c.DoQuery(ctx, quic.DefaultMaxObjectSize, request, &response); err == nil {
		t.Fatal("request above 4 MiB accepted")
	}
	request.URL = "/"
	if err := c.DoQuery(ctx, quic.DefaultMaxObjectSize, request, &response); err != nil {
		t.Fatalf("peer unusable after oversized request: %v", err)
	}
	if got := handled.Load(); got != 2 {
		t.Fatalf("handled %d requests, want 2; oversized request must not reach the handler", got)
	}
}

func TestQUICHTTP(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			requestBody := bytes.Repeat([]byte("request body\n"), 100)
			responseBody := []byte("response over QUIC")
			srv := NewServer(nil, nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method || r.URL.Path != "/test" {
					t.Error("unexpected HTTP request")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request: %v", err)
					return
				}
				if method == http.MethodPost && !bytes.Equal(body, requestBody) {
					t.Errorf("unexpected POST body: %q", body)
				}
				if method == http.MethodGet && len(body) != 0 {
					t.Error("unexpected GET body")
				}
				_, _ = w.Write(responseBody)
			}))
			t.Cleanup(func() { _ = srv.Stop() })
			server, addr := startQUICGateway(t)
			serverClients := make(chan *quicClient, 1)
			server.SetConnectionHandler(func(peer *quic.Peer) error {
				c := newQUICClient(peer, 30*time.Second)
				c.SetOnQuery(srv.handle(c, "test", peer.RemoteAddr()))
				serverClients <- c
				return nil
			})
			client, _ := startQUICGateway(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			peer, err := client.DialDefault(ctx, server.PublicKey(), addr)
			if err != nil {
				t.Fatal(err)
			}
			c := newQUICClient(peer, 30*time.Second)
			defer c.Close()
			id := bytes.Repeat([]byte{1}, 32)
			stream := &payloadStream{Data: io.NopCloser(bytes.NewReader(requestBody))}
			var pulls atomic.Int32
			c.SetOnQuery(func(transferId []byte, q *rldp.Query) error {
				req, ok := q.Data.(GetNextPayloadPart)
				if !ok || !bytes.Equal(req.ID, id) {
					return fmt.Errorf("unexpected reverse query %T", q.Data)
				}
				pulls.Add(1)
				part, err := handleGetPart(req, stream)
				if err != nil {
					return err
				}
				return c.SendAnswer(ctx, q.MaxAnswerSize, q.Timeout, q.ID, transferId, part)
			})
			req := Request{ID: id, Method: method, URL: "http://test.ton/test", Version: "HTTP/1.1"}
			if method == http.MethodPost {
				req.Headers = []Header{{Name: "Content-Length", Value: fmt.Sprint(len(requestBody))}}
			}
			var response Response
			if err := c.DoQuery(ctx, quic.DefaultMaxObjectSize, req, &response); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || response.NoPayload {
				t.Fatalf("unexpected response: %+v", response)
			}
			var body bytes.Buffer
			if err := srv.fetchPayload(ctx, id, c, &body); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body.Bytes(), responseBody) {
				t.Fatalf("unexpected response body: %q", body.Bytes())
			}
			if method == http.MethodPost && pulls.Load() == 0 {
				t.Fatal("POST body was not pulled on the same peer")
			}
			if method == http.MethodGet && pulls.Load() != 0 {
				t.Fatal("GET unexpectedly pulled a request body")
			}
			serverClient := <-serverClients
			disconnected := make(chan struct{})
			serverClient.SetOnDisconnect(func() { close(disconnected) })
			if err := serverClient.peer.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-disconnected:
			case <-ctx.Done():
				t.Fatal("disconnect callback not called")
			}
			serverClient.mx.Lock()
			pending := len(serverClient.pending)
			serverClient.mx.Unlock()
			if pending != 0 {
				t.Fatal("pending queries remain after disconnect")
			}
		})
	}
}

func TestQUICMalformedInput(t *testing.T) {
	server, addr := startQUICGateway(t)
	var calls atomic.Int32
	server.SetConnectionHandler(func(peer *quic.Peer) error {
		c := newQUICClient(peer, 30*time.Second)
		c.SetOnQuery(func(_ []byte, q *rldp.Query) error {
			calls.Add(1)
			return c.SendAnswer(context.Background(), q.MaxAnswerSize, q.Timeout, q.ID, nil, Response{Version: "HTTP/1.1", StatusCode: 200, NoPayload: true})
		})
		return nil
	})
	client, _ := startQUICGateway(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer, err := client.DialDefault(ctx, server.PublicKey(), addr)
	if err != nil {
		t.Fatal(err)
	}
	unexpected, err := tl.Serialize(PayloadPart{IsLast: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := tl.Serialize(Request{ID: make([]byte, 32), Method: "GET", URL: "/", Version: "HTTP/1.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{nil, {1, 2, 3}, unexpected, append(bytes.Clone(valid), 0), valid[:len(valid)-1]} {
		if _, err := peer.Query(ctx, payload, quic.DefaultMaxObjectSize); err == nil {
			t.Errorf("malformed query %x accepted", payload)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed input reached HTTP handler")
	}
	// A valid query still succeeds after malformed input on the same connection.
	c := newQUICClient(peer, 30*time.Second)
	var response Response
	if err := c.DoQuery(ctx, 0, Request{ID: make([]byte, 32), Method: "GET", URL: "/", Version: "HTTP/1.1"}, &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

// Adapter failure tests also verify that the single available stream slot is reusable.
func quicFailureFixture(t *testing.T, timeout time.Duration, configure func(*quicClient, *quic.Peer)) (*quic.Peer, *quicClient) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := quic.DefaultLimits()
	limits.MaxConcurrentIncomingStreamsPerConnection = 1
	server, err := quic.NewGatewayWithLimits(limits, key)
	if err != nil {
		t.Fatal(err)
	}
	adapters := make(chan *quicClient, 1)
	server.SetConnectionHandler(func(peer *quic.Peer) error {
		c := newQUICClient(peer, timeout)
		configure(c, peer)
		adapters <- c
		return nil
	})
	addr := serveQUICGateway(t, server)
	client, _ := startQUICGateway(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peer, err := client.DialDefault(ctx, server.PublicKey(), addr)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-adapters:
		return peer, c
	case <-ctx.Done():
		t.Fatal("server adapter was not initialized")
		return nil, nil
	}
}

func checkQUICFailure(t *testing.T, peer *quic.Peer, c *quicClient, query tl.Serializable) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wire, err := tl.Serialize(query, true)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := peer.Query(ctx, wire, quic.DefaultMaxObjectSize); err == nil {
		t.Fatal("failed handler returned success")
	}
	if time.Since(started) >= time.Second {
		t.Fatal("failed handler held the stream until the client deadline")
	}
	c.mx.Lock()
	pending := len(c.pending)
	c.mx.Unlock()
	if pending != 0 {
		t.Fatalf("failed query left %d pending entries", pending)
	}
	// With one incoming stream slot, this can succeed only if the failed stream ended.
	wire, err = tl.Serialize(Request{ID: make([]byte, 32), Method: "GET", URL: "/ok", Version: "HTTP/1.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := peer.Query(ctx, wire, quic.DefaultMaxObjectSize)
	if err != nil {
		t.Fatalf("stream slot was not reusable: %v", err)
	}
	obj, err := parseQUICHTTP(data)
	if err != nil {
		t.Fatal(err)
	}
	if response, ok := obj.(Response); !ok || response.StatusCode != 204 {
		t.Fatalf("unexpected recovery response: %+v", obj)
	}
}

func TestQUICHandlerFailureReleasesStream(t *testing.T) {
	for _, failure := range []string{"error", "panic", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			peer, c := quicFailureFixture(t, 50*time.Millisecond, func(c *quicClient, _ *quic.Peer) {
				c.SetOnQuery(func(_ []byte, q *rldp.Query) error {
					if q.Timeout == 0 {
						return fmt.Errorf("missing query deadline")
					}
					if q.Data.(Request).URL == "/ok" {
						return c.SendAnswer(context.Background(), q.MaxAnswerSize, q.Timeout, q.ID, nil, Response{StatusCode: 204, NoPayload: true})
					}
					switch failure {
					case "error":
						return fmt.Errorf("test query handler error")
					case "panic":
						panic("test query handler panic")
					default:
						return nil
					}
				})
			})
			checkQUICFailure(t, peer, c, Request{ID: make([]byte, 32), Method: "GET", URL: "/fail", Version: "HTTP/1.1"})
		})
	}
}

func TestQUICAnswerLimit(t *testing.T) {
	peer, _ := quicFailureFixture(t, time.Second, func(c *quicClient, _ *quic.Peer) {
		c.SetOnQuery(func(_ []byte, q *rldp.Query) error {
			return c.SendAnswer(context.Background(), q.MaxAnswerSize, q.Timeout, q.ID, nil, Response{StatusCode: 204, NoPayload: true})
		})
	})
	client := newQUICClient(peer, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := Request{ID: make([]byte, 32), Method: "GET", URL: "/ok", Version: "HTTP/1.1"}
	var response Response
	if err := client.DoQuery(ctx, 1, request, &response); err == nil {
		t.Fatal("answer exceeded the caller's limit")
	}
	if err := client.DoQuery(ctx, quic.DefaultMaxObjectSize, request, &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 204 {
		t.Fatalf("unexpected answer: %+v", response)
	}
}
