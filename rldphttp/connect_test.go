package rldphttp

import (
	"bytes"
	"context"

	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

type connectTestClient struct {
	mockRLDP
	upload []byte
}

func (c *connectTestClient) DoQuery(_ context.Context, _ uint64, _, result tl.Serializable) error {
	*result.(*PayloadPart) = PayloadPart{Data: c.upload, IsLast: true}
	return nil
}

func TestConnectUploadHalfClosePreservesResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	upload := []byte("request before TCP half-close")
	reply := []byte("response after upload EOF")
	origin := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			origin <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		body, err := io.ReadAll(conn)
		if err == nil && !bytes.Equal(body, upload) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = conn.Write(reply)
		}
		origin <- err
	}()
	srv := NewServer(nil, nil, nil, nil)
	defer srv.Stop()
	_, listenPort, _ := net.SplitHostPort(listener.Addr().String())
	allowedPort, _ := strconv.Atoi(listenPort)
	srv.ConnectDialContext = DialConnectTo("127.0.0.1", uint16(allowedPort))
	client := &connectTestClient{upload: upload}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	id := bytes.Repeat([]byte{1}, 32)
	req := Request{ID: id, Method: "CONNECT", URL: net.JoinHostPort("example.adnl", port), Version: "HTTP/1.1"}
	q := &rldp.Query{ID: bytes.Repeat([]byte{2}, 32), MaxAnswerSize: _RLDPMaxAnswerSize, Timeout: uint32(time.Now().Add(5 * time.Second).Unix())}
	if err = srv.handleConnect(nil, client, nil, q, req, ""); err != nil {
		t.Fatal(err)
	}
	stream := srv.activeRequests.getAndRefresh(payloadKey("", id), time.Now().Add(time.Minute))
	if stream == nil {
		t.Fatal("missing CONNECT download stream")
	}
	defer stream.finish()
	got, err := io.ReadAll(stream.Data)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("response=%q err=%v", got, err)
	}
	if err := <-origin; err != nil {
		t.Fatal(err)
	}
	client.mx.Lock()
	defer client.mx.Unlock()
	response := client.answers[0].(Response)
	if response.StatusCode != 200 || response.NoPayload {
		t.Fatalf("invalid CONNECT response: %+v", response)
	}
}

func TestConnectDefaultPortPolicy(t *testing.T) {
	_, err := DialConnectTo("127.0.0.1")(context.Background(), "example.adnl:22")
	var dialError net.Error
	if err == nil || errors.As(err, &dialError) {
		t.Fatalf("expected a port policy rejection before dialing, got %v", err)
	}
}

type deferredConnectClient struct {
	mockRLDP
	ready    <-chan struct{}
	upload   []byte
	entered  chan struct{}
	returned chan struct{}
}

func (c *deferredConnectClient) DoQuery(ctx context.Context, _ uint64, _, result tl.Serializable) error {
	close(c.entered)
	defer close(c.returned)
	select {
	case <-c.ready:
		*result.(*PayloadPart) = PayloadPart{Data: c.upload, IsLast: true}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type observedConnectConn struct {
	*net.TCPConn
	closed chan struct{}
	once   sync.Once
}

func (c *observedConnectConn) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestConnectBackendHalfClosePreservesUpload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("data"), 3*1024*1024/4)
	origin := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			origin <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte("server-finished"))
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		if err == nil {
			var body []byte
			body, err = io.ReadAll(conn)
			if err == nil && !bytes.Equal(body, payload) {
				err = fmt.Errorf("backend got %d bytes, want %d", len(body), len(payload))
			}
		}
		origin <- err
	}()
	ready := make(chan struct{})
	client := &deferredConnectClient{ready: ready, upload: payload, entered: make(chan struct{}), returned: make(chan struct{})}
	srv := NewServer(nil, nil, nil, nil)
	defer srv.Stop()
	closed := make(chan struct{})
	srv.ConnectDialContext = func(ctx context.Context, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &observedConnectConn{TCPConn: conn.(*net.TCPConn), closed: closed}, nil
	}
	id := bytes.Repeat([]byte{4}, 32)
	q := &rldp.Query{ID: bytes.Repeat([]byte{5}, 32), MaxAnswerSize: _RLDPMaxAnswerSize, Timeout: uint32(time.Now().Add(5 * time.Second).Unix())}
	if err := srv.handleConnect(nil, client, nil, q, Request{ID: id, Method: "CONNECT", URL: "manifesto.ton:443", Version: "HTTP/1.1"}, ""); err != nil {
		t.Fatal(err)
	}
	<-client.entered
	var got []byte
	for seq := int32(0); ; seq++ {
		next := *q
		next.Data = GetNextPayloadPart{ID: id, Seqno: seq, MaxChunkSize: 1024}
		if err := srv.handleQuery(nil, nil, client, "", nil, nil, &next); err != nil {
			t.Fatal(err)
		}
		client.mx.Lock()
		part := client.answers[len(client.answers)-1].(*PayloadPart)
		client.mx.Unlock()
		got = append(got, part.Data...)
		if part.IsLast {
			break
		}
	}
	if string(got) != "server-finished" {
		t.Fatalf("download %q", got)
	}
	select {
	case <-closed:
		t.Fatal("response EOF closed the still-active upload")
	default:
	}
	if srv.activeRequests.getAndRefresh(payloadKey("", id), time.Now().Add(time.Minute)) == nil {
		t.Fatal("active upload lost its cleanup registration")
	}
	close(ready)
	if err := <-origin; err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("completed tunnel not closed")
	}
	if srv.activeRequests.getAndRefresh(payloadKey("", id), time.Now()) != nil {
		t.Fatal("completed tunnel leaked")
	}
}

func TestConnectCancellationStopsUpload(t *testing.T) {
	ready := make(chan struct{})
	client := &deferredConnectClient{ready: ready, entered: make(chan struct{}), returned: make(chan struct{})}
	srv := NewServer(nil, nil, nil, nil)
	defer srv.Stop()
	conn, peer := net.Pipe()
	defer peer.Close()
	srv.ConnectDialContext = func(context.Context, string) (net.Conn, error) { return conn, nil }
	id := bytes.Repeat([]byte{6}, 32)
	q := &rldp.Query{ID: id, MaxAnswerSize: _RLDPMaxAnswerSize, Timeout: uint32(time.Now().Add(5 * time.Second).Unix())}
	if err := srv.handleConnect(nil, client, nil, q, Request{ID: id, Method: "CONNECT", URL: "manifesto.ton:443", Version: "HTTP/1.1"}, ""); err != nil {
		t.Fatal(err)
	}
	<-client.entered
	_ = srv.Stop()
	select {
	case <-client.returned:
	case <-time.After(time.Second):
		t.Fatal("cancelled upload did not stop")
	}
	if srv.activeRequests.getAndRefresh(payloadKey("", id), time.Now()) != nil {
		t.Fatal("cancelled tunnel leaked")
	}
}
