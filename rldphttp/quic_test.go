package rldphttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	adnladdress "github.com/xssnick/tonutils-go/adnl/address"
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

// Keep the server's periodic DHT refresh local to this loopback test.
type quicTestDHT struct{}

func (quicTestDHT) StoreAddress(context.Context, adnladdress.List, time.Duration, ed25519.PrivateKey) (int, []byte, error) {
	return 1, nil, nil
}
func (quicTestDHT) FindAddresses(context.Context, []byte) (*adnladdress.List, ed25519.PublicKey, error) {
	return nil, nil, nil
}
func (quicTestDHT) Close() {}

func TestServerQUIC(t *testing.T) {
	for _, mode := range []string{"quic", "port busy", "tunnel"} {
		t.Run(mode, func(t *testing.T) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			// Reserve both derived ports before starting; keep QUIC occupied only
			// in the failure case to verify that RLDP startup remains independent.
			var rldpConn, quicReservation net.PacketConn
			var quicAddr string
			for attempt := 0; attempt < 10; attempt++ {
				rldpConn, err = net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				if rldpConn.LocalAddr().(*net.UDPAddr).Port > 64535 {
					_ = rldpConn.Close()
					continue
				}
				endpoint, endpointErr := quic.PeerEndpoint([]adnladdress.Address{adnladdress.UDP{IP: net.IPv4(127, 0, 0, 1), Port: int32(rldpConn.LocalAddr().(*net.UDPAddr).Port)}})
				if endpointErr != nil {
					t.Fatal(endpointErr)
				}
				if endpoint.Port() != 0 {
					quicAddr = endpoint.String()
					quicReservation, err = net.ListenPacket("udp", quicAddr)
					if err == nil {
						break
					}
				}
				_ = rldpConn.Close()
			}
			if quicReservation == nil {
				t.Fatal("failed to reserve loopback port pair")
			}
			defer quicReservation.Close()
			defer rldpConn.Close()
			addr := rldpConn.LocalAddr().String()
			manager := adnl.NewMultiNetReader(rldpConn)
			defer manager.Close()
			gate := adnl.NewGatewayWithNetManager(key, manager)
			srv := NewServer(key, gate, quicTestDHT{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
					w.WriteHeader(500)
					return
				}
				if r.URL.Path != "/test" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				_, _ = fmt.Fprintf(w, "%s:%s", r.Method, body)
			}))
			if mode != "port busy" {
				_ = quicReservation.Close()
			}
			serve := srv.ListenAndServe
			if mode == "tunnel" {
				serve = srv.ListenAndServeTunnel
			}
			done := make(chan error, 1)
			go func() { done <- serve(addr) }()
			t.Cleanup(func() {
				if err := srv.Stop(); err != nil {
					t.Errorf("stop server: %v", err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("serve HTTP: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("server did not stop")
				}
			})

			_, clientKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			clientGateway := adnl.NewGateway(clientKey)
			if err := clientGateway.StartClient(); err != nil {
				t.Fatal(err)
			}
			defer clientGateway.Close()
			peer, err := clientGateway.RegisterClient(addr, key.Public().(ed25519.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			wantCapabilities := CapabilityRLDP2
			if mode == "quic" {
				wantCapabilities |= CapabilityQUIC
			}
			for {
				var capabilities Capabilities
				if err := peer.Query(ctx, GetCapabilities{}, &capabilities); err != nil {
					t.Fatal(err)
				}
				if capabilities.Value == wantCapabilities {
					break
				}
				if capabilities.Value != CapabilityRLDP2 {
					t.Fatalf("unexpected capabilities: %d", capabilities.Value)
				}
				select {
				case <-time.After(10 * time.Millisecond):
				case <-ctx.Done():
					t.Fatal("QUIC did not become ready")
				}
			}
			var transport RLDP
			if mode == "quic" {
				client, _ := startQUICGateway(t)
				quicPeer, err := client.DialDefault(ctx, key.Public().(ed25519.PublicKey), quicAddr)
				if err != nil {
					t.Fatal(err)
				}
				transport = newQUICClient(quicPeer, 30*time.Second)
			} else {
				transport = rldp.NewClientV2(peer)
			}
			defer transport.Close()
			for index, method := range []string{http.MethodGet, http.MethodPost} {
				id := bytes.Repeat([]byte{byte(index + 1)}, 32)
				requestBody := ""
				if method == http.MethodPost {
					requestBody = "POST body pulled on the same peer"
				}
				stream := &payloadStream{Data: io.NopCloser(bytes.NewBufferString(requestBody))}
				var pulls atomic.Int32
				transport.SetOnQuery(func(transferID []byte, query *rldp.Query) error {
					req, ok := query.Data.(GetNextPayloadPart)
					if !ok || !bytes.Equal(req.ID, id) {
						return fmt.Errorf("unexpected body query: %T", query.Data)
					}
					pulls.Add(1)
					part, err := handleGetPart(req, stream)
					if err != nil {
						return err
					}
					return transport.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferID, part)
				})
				request := Request{ID: id, Method: method, URL: "http://test.ton/test", Version: "HTTP/1.1"}
				if requestBody != "" {
					request.Headers = []Header{{Name: "Content-Length", Value: fmt.Sprint(len(requestBody))}}
				}
				var response Response
				if err := transport.DoQuery(ctx, _RLDPMaxAnswerSize, request, &response); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != 200 || response.NoPayload {
					t.Fatalf("unexpected %s response: %+v", method, response)
				}
				var body bytes.Buffer
				if err := srv.fetchPayload(ctx, id, transport, &body); err != nil {
					t.Fatal(err)
				}
				if want := method + ":" + requestBody; body.String() != want {
					t.Fatalf("body = %q, want %q", body.String(), want)
				}
				if method == http.MethodPost && pulls.Load() == 0 {
					t.Fatal("request body was not pulled")
				}
			}
			select {
			case err := <-done:
				t.Fatalf("server stopped prematurely: %v", err)
			default:
			}
			if mode == "tunnel" {
				unbound, err := net.ListenPacket("udp", quicAddr)
				if err != nil {
					t.Fatalf("tunnel mode bound the QUIC port: %v", err)
				}
				_ = unbound.Close()
			}
			if err := srv.Stop(); err != nil {
				t.Fatal(err)
			}
			if srv.capabilities() != CapabilityRLDP2 {
				t.Fatal("QUIC still advertised after Stop")
			}
			if mode == "quic" {
				rebound, err := net.ListenPacket("udp", quicAddr)
				if err != nil {
					t.Fatalf("QUIC socket was not released: %v", err)
				}
				_ = rebound.Close()
			}
		})
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

// Server wiring failure tests exercise errors recovered by the asynchronous runQuery path.
type quicErrorReader struct{}

func (quicErrorReader) Read([]byte) (int, error) { return 0, fmt.Errorf("test payload reader error") }
func (quicErrorReader) Close() error             { return nil }

func TestQUICRunQueryFailureReleasesStream(t *testing.T) {
	for _, failure := range []string{"error", "panic"} {
		t.Run(failure, func(t *testing.T) {
			srv := NewServer(nil, nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/panic" {
					panic("test HTTP handler panic")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(func() { _ = srv.Stop() })
			id := make([]byte, 32)
			if err := srv.registerPayloadStream(hex.EncodeToString(id), &payloadStream{Data: quicErrorReader{}}, nil); err != nil {
				t.Fatal(err)
			}
			peer, c := quicFailureFixture(t, srv.Timeout, func(c *quicClient, peer *quic.Peer) { c.SetOnQuery(srv.handle(c, "test", peer.RemoteAddr())) })
			var query tl.Serializable = GetNextPayloadPart{ID: id, MaxChunkSize: 1}
			if failure == "panic" {
				query = Request{ID: id, Method: "GET", URL: "/panic", Version: "HTTP/1.1"}
			}
			checkQUICFailure(t, peer, c, query)
		})
	}
}

func TestStopDuringQUICStartup(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(key, nil, nil, http.NotFoundHandler())
	t.Cleanup(func() { _ = srv.Stop() })
	bound := make(chan net.Addr, 1)
	resume := make(chan struct{})
	var resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	defer release()
	startup := make(chan error, 1)
	go func() {
		startup <- srv.startQUICWithListener("127.0.0.1:0", func(network, addr string) (net.PacketConn, error) {
			conn, err := net.ListenPacket(network, "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			bound <- conn.LocalAddr()
			<-resume
			return conn, nil
		})
	}()
	var addr net.Addr
	select {
	case addr = <-bound:
	case err := <-startup:
		t.Fatalf("startup failed before bind: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not bind")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- srv.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on QUIC startup")
	}
	release()
	select {
	case err := <-startup:
		if !errors.Is(err, ErrServerStopped) {
			t.Fatalf("startup error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startup did not finish after Stop")
	}
	srv.mx.RLock()
	published := srv.quicServer != nil || srv.quicConn != nil
	srv.mx.RUnlock()
	if published {
		t.Fatal("QUIC was published after Stop")
	}
	conn, err := net.ListenPacket("udp", addr.String())
	if err != nil {
		t.Fatalf("startup leaked its socket: %v", err)
	}
	_ = conn.Close()
}

func TestQUICRejectsWrappingPort(t *testing.T) {
	srv := NewServer(nil, nil, nil, http.NotFoundHandler())
	if err := srv.startQUICWithListener("127.0.0.1:64536", func(string, string) (net.PacketConn, error) {
		t.Error("invalid port reached the listener")
		return nil, fmt.Errorf("unexpected bind")
	}); err == nil {
		t.Fatal("wrapping QUIC port was accepted")
	}
}
