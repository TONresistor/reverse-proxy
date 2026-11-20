package rldphttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/ton-utils/reverse-proxy/internal/quicwire"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type quicSourcePacketConn struct {
	net.PacketConn
	source chan string
}

func (c *quicSourcePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		select {
		case c.source <- addr.String():
		default:
		}
	}
	return n, addr, err
}

func TestQUICServerThroughTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, exit := testTunnel(t, ctx)
	ad, shared := quicwire.Split(conn)
	defer ad.Close()
	_, key, _ := ed25519.GenerateKey(nil)
	body := bytes.Repeat([]byte("tunneled response"), 10000)
	payload := bytes.Repeat([]byte("HTTPS through ADNL tunnel"), 2048)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = w.Write(payload)
	}))
	defer origin.Close()
	_, portText, _ := net.SplitHostPort(origin.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	server := NewServer(key, nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Stop()
	incoming := &quicSourcePacketConn{PacketConn: shared, source: make(chan string, 1)}
	server.UseQUICTunnel(incoming)
	server.ConnectDialContext = DialConnectTo("127.0.0.1", uint16(port))
	// No local UDP address is needed when the tunnel owns the socket.
	if err := server.startQUIC(""); err != nil {
		t.Fatal(err)
	}
	_, clientKey, _ := ed25519.GenerateKey(nil)
	limits := quic.DefaultLimits()

	client, err := quic.NewGatewayWithLimits(limits, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Use the same address family as the fixture's ADNL nodes, avoiding
	// Darwin's cross-family ephemeral-port collisions.
	if got := server.capabilitiesFor(CapabilityQUIC | CapabilityRLDP2); got != CapabilityRLDP2 {
		t.Fatalf("legacy offer: %d", got)
	}
	if got := server.capabilitiesFor(CapabilityQUIC | CapabilityQUICEnvelope | CapabilityRLDP2); got != CapabilityRLDP2|CapabilityQUICEnvelope {
		t.Fatalf("envelope offer: %d", got)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plain, framed := quicwire.Split(pc)
	defer plain.Close()
	defer framed.Close()
	go func() { _ = client.Serve(framed) }()
	if err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	clientAddr := pc.LocalAddr().String()
	bound, err := net.ResolveUDPAddr("udp4", clientAddr)
	if err != nil || !bound.IP.IsLoopback() || bound.IP.To4() == nil || bound.Port == 0 {
		t.Fatalf("QUIC client needs a reserved IPv4 loopback socket: %s, %v", clientAddr, err)
	}
	peer, err := client.DialDefault(ctx, key.Public().(ed25519.PublicKey), exit.String())
	if err != nil {
		t.Fatal(err)
	}
	c := newQUICClient(peer, 30*time.Second)
	id := bytes.Repeat([]byte{1}, 32)
	var response Response
	if err := c.DoQuery(ctx, 4096, Request{ID: id, Method: "GET", URL: "http://manifesto.ton/", Version: "HTTP/1.1"}, &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("status %d", response.StatusCode)
	}
	select {
	case source := <-incoming.source:
		if source != clientAddr {
			t.Fatalf("QUIC source through tunnel %s, want reserved client socket %s", source, clientAddr)
		}
	case <-ctx.Done():
		t.Fatal("tunnel did not deliver QUIC from the reserved client socket")
	}
	var got []byte
	for seq := int32(0); ; seq++ {
		var part PayloadPart
		if err := c.DoQuery(ctx, uint64(len(body)+4096), GetNextPayloadPart{ID: id, Seqno: seq, MaxChunkSize: 65536}, &part); err != nil {
			t.Fatal(err)
		}
		got = append(got, part.Data...)
		if part.IsLast {
			break
		}
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("response length %d, want %d", len(got), len(body))
	}
	post := bytes.Repeat([]byte("P"), 1<<20)
	stream := &payloadStream{Data: io.NopCloser(bytes.NewReader(post))}
	var pulls atomic.Int32
	c.SetOnQuery(func(transferID []byte, query *rldp.Query) error {
		req, ok := query.Data.(GetNextPayloadPart)
		if !ok {
			return fmt.Errorf("unexpected body query %T", query.Data)
		}
		pulls.Add(1)
		part, err := handleGetPart(req, stream)
		if err != nil {
			return err
		}
		return c.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferID, part)
	})
	id = bytes.Repeat([]byte{3}, 32)
	if err := c.DoQuery(ctx, 4096, Request{ID: id, Method: http.MethodPost, URL: "http://manifesto.ton/", Version: "HTTP/1.1", Headers: []Header{{Name: "Content-Length", Value: strconv.Itoa(len(post))}}}, &response); err != nil {
		t.Fatal(err)
	}
	got = nil
	for seq := int32(0); ; seq++ {
		var part PayloadPart
		if err := c.DoQuery(ctx, uint64(len(post)+4096), GetNextPayloadPart{ID: id, Seqno: seq, MaxChunkSize: 65536}, &part); err != nil {
			t.Fatal(err)
		}
		got = append(got, part.Data...)
		if part.IsLast {
			break
		}
	}
	if response.StatusCode != 200 || !bytes.Equal(got, post) || pulls.Load() < 2 {
		t.Fatalf("POST status=%d length=%d pulls=%d", response.StatusCode, len(got), pulls.Load())
	}

	testQUICHTTPSConnect(t, ctx, c, portText, payload, origin.Certificate())
}

func testQUICHTTPSConnect(t *testing.T, ctx context.Context, c *quicClient, portText string, payload []byte, cert *x509.Certificate) {
	t.Helper()
	browser, wire := net.Pipe()
	defer browser.Close()
	defer wire.Close()
	_ = browser.SetDeadline(time.Now().Add(10 * time.Second))
	_ = wire.SetDeadline(time.Now().Add(10 * time.Second))
	c.SetOnQuery(func(_ []byte, q *rldp.Query) error {
		part, ok := q.Data.(GetNextPayloadPart)
		if !ok {
			return fmt.Errorf("unexpected upload query %T", q.Data)
		}
		buf := make([]byte, part.MaxChunkSize)
		n, err := wire.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			return err
		}
		return c.SendAnswer(ctx, q.MaxAnswerSize, q.Timeout, q.ID, nil, PayloadPart{Data: buf[:n], IsLast: err != nil})
	})
	id := bytes.Repeat([]byte{2}, 32)
	var response Response
	if err := c.DoQuery(ctx, 4096, Request{ID: id, Method: "CONNECT", URL: net.JoinHostPort("manifesto.ton", portText), Version: "HTTP/1.1"}, &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("CONNECT status %d", response.StatusCode)
	}
	downloaded := make(chan error, 1)
	go func() {
		for seq := int32(0); ; seq++ {
			var part PayloadPart
			if err := c.DoQuery(ctx, 70000, GetNextPayloadPart{ID: id, Seqno: seq, MaxChunkSize: 65536}, &part); err != nil {
				downloaded <- err
				return
			}
			if len(part.Data) > 0 {
				if _, err := wire.Write(part.Data); err != nil {
					downloaded <- err
					return
				}
			}
			if part.IsLast {
				downloaded <- nil
				return
			}
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	tlsConn := tls.Client(browser, &tls.Config{RootCAs: roots, ServerName: cert.DNSNames[0]})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://manifesto.ton/", nil)
	req.Close = true
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !bytes.Equal(got, payload) {
		t.Fatalf("HTTPS status=%d length=%d err=%v", resp.StatusCode, len(got), err)
	}
	_ = browser.Close()
	_ = wire.Close()
	select {
	case err := <-downloaded:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
