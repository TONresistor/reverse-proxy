package rldphttp

import (
	"context"

	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl/rldp"
)

type tunnelReader struct{ net.Conn }

func (r tunnelReader) Read(p []byte) (int, error) {
	// Return an idle part before RLDP's default 15-second query deadline.
	_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
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

func (s *Server) handleConnect(lease *requestLease, client RLDP, transferID []byte, q *rldp.Query, req Request, peerID string) error {
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
	duplex := &connectReadCloser{tunnelReader: tunnelReader{conn}, cancel: cancel}
	stream := &payloadStream{Data: duplex, ValidTill: time.Now().Add(s.Timeout), onResponseEOF: duplex.finishDownload}
	key := payloadKey(peerID, req.ID)
	duplex.finish = func() {
		s.activeRequests.deleteIfSame(key, stream)
		stream.finish()
	}
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
	upload := &connectActivityWriter{Writer: conn, touch: func() {
		s.activeRequests.refreshIfSame(key, stream, time.Now().Add(s.Timeout))
	}}
	go func() {
		// Upload EOF only shuts down TCP writes, preserving a final peer response.
		if err := s.fetchPayload(ctx, req.ID, client, upload); err != nil {
			s.activeRequests.deleteIfSame(key, stream)
			stream.finish()
			cancel()
			return
		}
		if tcp, ok := conn.(interface{ CloseWrite() error }); ok {
			if err := tcp.CloseWrite(); err != nil {
				duplex.finish()
				return
			}
		} else {
			duplex.finish()
			return
		}
		duplex.finishUpload()
	}()
	return nil
}

type connectReadCloser struct {
	tunnelReader
	cancel       context.CancelFunc
	mx           sync.Mutex
	uploadDone   bool
	downloadDone bool
	finish       func()
}

func (c *connectReadCloser) Close() error { c.cancel(); return c.Conn.Close() }

func (c *connectReadCloser) finishUpload() {
	c.mx.Lock()
	c.uploadDone = true
	done := c.downloadDone
	c.mx.Unlock()
	if done {
		c.finish()
	}
}

func (c *connectReadCloser) finishDownload() {
	c.mx.Lock()
	c.downloadDone = true
	done := c.uploadDone
	c.mx.Unlock()
	if done {
		c.finish()
	}
}

// Upload progress keeps a half-closed CONNECT session alive without changing
// expiry for ordinary HTTP payloads or an upload that has stopped progressing.
type connectActivityWriter struct {
	io.Writer
	touch func()
}

func (w *connectActivityWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.touch()
	}
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.touch()
	}
	return n, err
}
