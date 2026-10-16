package rldphttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
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
	if err = srv.handleConnect(nil, client, nil, q, req); err != nil {
		t.Fatal(err)
	}
	stream := srv.activeRequests.getAndRefresh(hex.EncodeToString(id), time.Now().Add(time.Minute))
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
