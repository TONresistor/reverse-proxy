package rldphttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
)

func TestQUICHTTPBidirectional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, serverKey, _ := ed25519.GenerateKey(nil)
	_, clientKey, _ := ed25519.GenerateKey(nil)
	server, err := quic.NewGateway(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := quic.NewGateway(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	body := bytes.Repeat([]byte("http-payload"), 30000)
	server.SetConnectionHandler(func(peer *quic.Peer) error {
		c := &quicClient{peer: peer}
		c.SetOnQuery(func(_ []byte, q *rldp.Query) error {
			go func() {
				var part PayloadPart
				if err := c.DoQuery(ctx, uint64(len(body)+1024), GetNextPayloadPart{ID: make([]byte, 32), MaxChunkSize: int32(len(body))}, &part); err != nil {
					t.Error(err)
					return
				}
				if !bytes.Equal(part.Data, body) {
					t.Error("upload payload mismatch")
				}
				if err := c.SendAnswer(ctx, q.MaxAnswerSize, q.Timeout, q.ID, nil, PayloadPart{Data: part.Data, IsLast: true}); err != nil {
					t.Error(err)
				}
			}()
			return nil
		})
		return nil
	})
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	go func() { _ = server.Serve(socket) }()
	if err := server.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	peer, err := client.DialDefault(ctx, serverKey.Public().(ed25519.PublicKey), socket.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := &quicClient{peer: peer}
	c.SetOnQuery(func(_ []byte, q *rldp.Query) error {
		return c.SendAnswer(ctx, q.MaxAnswerSize, q.Timeout, q.ID, nil, PayloadPart{Data: body, IsLast: true})
	})
	var part PayloadPart
	if err := c.DoQuery(ctx, uint64(len(body)+1024), Request{ID: make([]byte, 32), Method: "POST", URL: "/", Version: "HTTP/1.1"}, &part); err != nil {
		t.Fatal(err)
	}
	if !part.IsLast || !bytes.Equal(part.Data, body) {
		t.Fatal("download payload mismatch")
	}
}
