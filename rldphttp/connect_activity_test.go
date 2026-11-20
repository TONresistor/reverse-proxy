package rldphttp

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	adnladdress "github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/rldp"
)

func TestConnectActivityRefreshesOnlyLiveSession(t *testing.T) {
	registry := newActiveRequestRegistry()
	initial := time.Unix(100, 0)
	renewed := initial.Add(time.Minute)
	old := &payloadStream{Data: io.NopCloser(bytes.NewReader(nil)), ValidTill: initial}
	replacement := &payloadStream{Data: io.NopCloser(bytes.NewReader(nil)), ValidTill: initial}
	defer old.finish()
	defer replacement.finish()
	registry.store("session", old)
	if !registry.refreshIfSame("session", old, renewed) || !old.ValidTill.Equal(renewed) {
		t.Fatal("live session was not refreshed")
	}
	if !registry.refreshIfSame("session", old, initial) || !old.ValidTill.Equal(renewed) {
		t.Fatal("delayed upload shortened the session deadline")
	}
	old.finish()
	if registry.refreshIfSame("session", old, renewed.Add(time.Minute)) || !old.ValidTill.Equal(renewed) {
		t.Fatal("finished session was refreshed")
	}
	registry.store("session", replacement)
	if registry.refreshIfSame("session", old, renewed) || !replacement.ValidTill.Equal(initial) {
		t.Fatal("stale upload refreshed replacement session")
	}
	registry.deleteIfSame("session", replacement)
	if registry.refreshIfSame("session", replacement, renewed) || registry.get("session") != nil {
		t.Fatal("removed session was resurrected")
	}
	if registry.refreshIfSame("missing", nil, renewed) {
		t.Fatal("nil session was refreshed")
	}
}

// Exercise both sides of the real reaper: upload progress survives download EOF,
// while a second CONNECT with no progress still expires on the same connection.
func TestConnectUploadProgressSurvivesReaperAfterDownloadEOF(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendDone := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var uploaded atomic.Int64
	go func() {
		for i := 0; i < 2; i++ {
			conn, e := backend.Accept()
			if e != nil {
				return
			}
			go func(index int, c net.Conn) {
				defer close(backendDone[index])
				defer c.Close()
				if e := c.(*net.TCPConn).CloseWrite(); e != nil {
					return
				}
				buf := make([]byte, 4096)
				for {
					n, e := c.Read(buf)
					if index == 0 {
						uploaded.Add(int64(n))
					}
					if e != nil {
						return
					}
				}
			}(i, conn)
		}
	}()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var socket, reservation net.PacketConn
	var qaddr string
	for i := 0; i < 30; i++ {
		socket, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := socket.LocalAddr().(*net.UDPAddr).Port
		if port <= 64535 {
			qaddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port+1000))
			reservation, err = net.ListenPacket("udp4", qaddr)
			if err == nil {
				break
			}
		}
		_ = socket.Close()
	}
	if reservation == nil {
		t.Fatal("no loopback port pair")
	}
	defer reservation.Close()
	defer socket.Close()
	manager := adnl.NewMultiNetReader(socket)
	defer manager.Close()
	gate := adnl.NewGatewayWithNetManager(key, manager)
	addr := socket.LocalAddr().(*net.UDPAddr)
	gate.SetAddressList([]adnladdress.Address{&adnladdress.UDP{IP: addr.IP, Port: int32(addr.Port)}})
	srv := NewServer(key, gate, quicTestDHT{}, nil)
	srv.Timeout = 300 * time.Millisecond
	srv.QUICPacketConn = reservation
	_, portText, _ := net.SplitHostPort(backend.Addr().String())
	port, _ := strconv.Atoi(portText)
	srv.ConnectDialContext = DialConnectTo("127.0.0.1", uint16(port))
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.ListenAndServe(socket.LocalAddr().String()) }()
	t.Cleanup(func() {
		_ = srv.Stop()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	ready := time.Now().Add(3 * time.Second)
	for srv.capabilitiesFor(0) != CapabilityRLDP2|CapabilityQUIC {
		if time.Now().After(ready) {
			t.Fatal("QUIC not ready")
		}
		time.Sleep(time.Millisecond)
	}
	clientGate, _ := startQUICGateway(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	peer, err := clientGate.DialDefault(ctx, key.Public().(ed25519.PublicKey), qaddr)
	if err != nil {
		t.Fatal(err)
	}
	client := newQUICClient(peer, 8*time.Second)
	peerID, _ := SerializeADNLAddress(clientGate.ID())
	activeID := bytes.Repeat([]byte{1}, 32)
	idleID := bytes.Repeat([]byte{2}, 32)
	var uploadParts atomic.Int64
	client.SetOnQuery(func(_ []byte, q *rldp.Query) error {
		req, ok := q.Data.(GetNextPayloadPart)
		if !ok {
			return fmt.Errorf("unexpected query %T", q.Data)
		}
		if bytes.Equal(req.ID, idleID) {
			return nil
		}
		if !bytes.Equal(req.ID, activeID) {
			return fmt.Errorf("unexpected request ID")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		uploadParts.Add(1)
		return client.SendAnswer(ctx, q.MaxAnswerSize, q.Timeout, q.ID, nil, PayloadPart{Data: []byte("still uploading"), IsLast: false})
	})
	for _, id := range [][]byte{activeID, idleID} {
		var response Response
		if err := client.DoQuery(ctx, 4096, Request{ID: id, Method: "CONNECT", URL: net.JoinHostPort("example.ton", portText), Version: "HTTP/1.1"}, &response); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatalf("CONNECT status %d", response.StatusCode)
		}
		var part PayloadPart
		if err := client.DoQuery(ctx, 4096, GetNextPayloadPart{ID: id, MaxChunkSize: 1024}, &part); err != nil {
			t.Fatal(err)
		}
		if !part.IsLast {
			t.Fatal("backend did not half-close download")
		}
	}
	select {
	case <-backendDone[0]:
		t.Fatalf("active upload closed after %d parts", uploadParts.Load())
	case <-backendDone[1]:
	case <-ctx.Done():
		t.Fatal("inactive CONNECT did not expire")
	}
	select {
	case <-backendDone[0]:
		t.Fatal("reaper closed active upload")
	default:
	}
	if uploadParts.Load() < 20 || uploaded.Load() < 100 {
		t.Fatalf("upload did not progress: %d parts, %d bytes", uploadParts.Load(), uploaded.Load())
	}
	if srv.activeRequests.get(payloadKey(peerID, activeID)) == nil {
		t.Fatal("active CONNECT removed")
	}
	if srv.activeRequests.get(payloadKey(peerID, idleID)) != nil {
		t.Fatal("inactive CONNECT retained")
	}
}
