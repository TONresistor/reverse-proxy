package rldphttp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/xssnick/tonutils-go/adnl/rldp"
)

type tunnelReader struct{ net.Conn }

func (r tunnelReader) Read(p []byte) (int, error) {
	_ = r.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := r.Conn.Read(p)
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return n, nil
	}
	return n, err
}

// DialConnectTo restricts CONNECT to the origin host and allowed ports (443 by default).
func DialConnectTo(originHost string, allowedPorts ...uint16) func(context.Context, string) (net.Conn, error) {
	if len(allowedPorts) == 0 {
		allowedPorts = []uint16{443}
	}
	ports := make(map[string]bool, len(allowedPorts))
	for _, port := range allowedPorts {
		ports[strconv.Itoa(int(port))] = true
	}
	return func(ctx context.Context, authority string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(authority)
		if err != nil {
			return nil, err
		}
		if !ports[port] {
			return nil, fmt.Errorf("CONNECT port %s is not configured", port)
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(originHost, port))
	}
}

func (s *Server) handleConnect(lease *requestLease, client RLDP, transferID []byte, q *rldp.Query, req Request) error {
	if s.ConnectDialContext == nil {
		return sendHTTPErrorResponse(client, q, transferID, req.Version, 405)
	}
	_, port, err := net.SplitHostPort(req.URL)
	if err != nil {
		return sendHTTPErrorResponse(client, q, transferID, req.Version, 400)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return sendHTTPErrorResponse(client, q, transferID, req.Version, 400)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := s.ConnectDialContext(ctx, req.URL)
	if err != nil {
		cancel()
		return sendHTTPErrorResponse(client, q, transferID, req.Version, 502)
	}
	stream := &payloadStream{Data: &connectReadCloser{tunnelReader: tunnelReader{conn}, cancel: cancel}, ValidTill: time.Now().Add(s.Timeout)}
	key := hex.EncodeToString(req.ID)
	if err = s.registerPayloadStream(key, stream, lease); err != nil {
		cancel()
		_ = conn.Close()
		return err
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	answerCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	err = client.SendAnswer(answerCtx, q.MaxAnswerSize, q.Timeout, q.ID, transferID, Response{Version: "HTTP/1.1", StatusCode: 200, Reason: "Connection Established", NoPayload: false})
	stop()
	if err != nil {
		s.activeRequests.deleteIfSame(key, stream)
		stream.finish()
		cancel()
		return err
	}
	go func() {
		// Upload EOF only shuts down TCP writes, preserving a final peer response.
		if err := s.fetchPayload(ctx, req.ID, client, conn); err != nil {
			s.activeRequests.deleteIfSame(key, stream)
			stream.finish()
			cancel()
			return
		}
		if tcp, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = conn.Close()
		}
	}()
	return nil
}

type connectReadCloser struct {
	tunnelReader
	cancel context.CancelFunc
}

func (c *connectReadCloser) Close() error { c.cancel(); return c.Conn.Close() }
