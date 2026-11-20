// Package quicwire carries QUIC over the UDP path provided by TON proxies.
package quicwire

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Version 1: six-byte discriminator, big-endian inner length, QUIC packet,
// then zeros up to 64 bytes. Upstream exits discard smaller UDP payloads.
const magic = "\x00TQIC\x01"
const header = len(magic) + 2
const minimum = 64
const maxWire = 2048 // Receive buffer of the upstream tunnel exit.

func marked(p []byte) bool { return len(p) >= len(magic) && string(p[:len(magic)]) == magic }
func unwrap(p []byte) []byte {
	if len(p) < minimum || len(p) > maxWire {
		return nil
	}
	n := int(binary.BigEndian.Uint16(p[len(magic):header]))
	if n == 0 || len(p) != max(minimum, header+n) {
		return nil
	}
	for _, v := range p[header+n:] {
		if v != 0 {
			return nil
		}
	}
	return p[header : header+n]
}

func sendFrame(pc net.PacketConn, p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 || len(p) > maxWire-header {
		return 0, errors.New("invalid QUIC envelope size")
	}
	b := make([]byte, max(minimum, header+len(p)))
	copy(b, magic)
	binary.BigEndian.PutUint16(b[len(magic):], uint16(len(p)))
	copy(b[header:], p)
	n, err := pc.WriteTo(b, addr)
	if err != nil {
		return 0, err
	}
	if n != len(b) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// Accept allows native and encapsulated connections on one QUIC listener.
// Replies use the mode of the incoming connection. There is no address cache.
func Accept(pc net.PacketConn) net.PacketConn { return &listener{PacketConn: pc} }

type framedAddr struct{ net.Addr }
type listener struct{ net.PacketConn }

var buffers = sync.Pool{New: func() any { return new([maxWire + 1]byte) }}

func (c *listener) ReadFrom(dst []byte) (int, net.Addr, error) {
	b := buffers.Get().(*[maxWire + 1]byte)
	defer buffers.Put(b)
	for {
		n, a, e := c.PacketConn.ReadFrom(b[:])
		if e != nil {
			return 0, nil, e
		}
		if n > maxWire {
			continue
		}
		p := b[:n]
		if marked(p) {
			p = unwrap(p)
			if p == nil || len(dst) < len(p) {
				continue
			}
			a = framedAddr{a}
		}
		return copy(dst, p), a, nil
	}
}
func (c *listener) WriteTo(p []byte, a net.Addr) (int, error) {
	if f, ok := a.(framedAddr); ok {
		return sendFrame(c.PacketConn, p, f.Addr)
	}
	return c.PacketConn.WriteTo(p, a)
}

type packet struct {
	b    []byte
	addr net.Addr
}
type shared struct {
	net.PacketConn
	mx        sync.Mutex
	open      int
	closing   chan struct{}
	stopped   chan struct{}
	readErr   error
	writing   *lane
	writeSlot chan struct{}
}
type lane struct {
	s      *shared
	framed bool
	in     chan packet
	closed chan struct{}
	// Deadlines and their notification channel are protected by s.mx.
	read, write time.Time
	changed     chan struct{}
}

// Split gives the caller two views of one socket. The first carries unmarked
// datagrams (ADNL on a tunnel), the second carries only encapsulated QUIC.
// Closing the last view closes the underlying connection.
func Split(pc net.PacketConn) (plain, framed net.PacketConn) {
	s := &shared{PacketConn: pc, open: 2, closing: make(chan struct{}), stopped: make(chan struct{}), writeSlot: make(chan struct{}, 1)}
	newLane := func(f bool) *lane {
		return &lane{s: s, framed: f, in: make(chan packet, 128), closed: make(chan struct{}), changed: make(chan struct{})}
	}
	a, q := newLane(false), newLane(true)
	go func() {
		defer close(s.stopped)
		var buf [maxWire + 1]byte
		for {
			n, addr, e := pc.ReadFrom(buf[:])
			if errors.Is(e, context.Canceled) {
				// Closing a retired ADNL tunnel wakes a read started before SwitchTo.
				select {
				case <-s.closing:
					s.readErr = net.ErrClosed
					return
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			if e != nil {
				s.readErr = e
				return
			}
			p := buf[:n]
			l := a
			if marked(p) {
				p = unwrap(p)
				if p == nil {
					continue
				}
				l = q
			}
			if len(p) > maxWire || len(l.in) == cap(l.in) {
				continue
			}
			select {
			case <-l.closed:
				continue
			default:
			}
			l.in <- packet{append([]byte(nil), p...), addr}
		}
	}()
	return a, q
}

func (l *lane) LocalAddr() net.Addr { return l.s.LocalAddr() }
func (l *lane) Close() error {
	s := l.s
	s.mx.Lock()
	select {
	case <-l.closed:
		s.mx.Unlock()
		return nil
	default:
	}
	close(l.closed)
	s.open--
	last := s.open == 0
	if last {
		close(s.closing)
	}
	if s.writing == l {
		_ = s.SetWriteDeadline(time.Now())
	}
	s.mx.Unlock()
	if last {
		return s.PacketConn.Close()
	}
	return nil
}

func (l *lane) setDeadline(t time.Time, read, write bool) error {
	s := l.s
	s.mx.Lock()
	defer s.mx.Unlock()
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
	}
	if read {
		l.read = t
	}
	if write {
		l.write = t
	}
	close(l.changed)
	l.changed = make(chan struct{})
	if write && s.writing == l {
		return s.SetWriteDeadline(t)
	}
	return nil
}
func (l *lane) SetDeadline(t time.Time) error      { return l.setDeadline(t, true, true) }
func (l *lane) SetReadDeadline(t time.Time) error  { return l.setDeadline(t, true, false) }
func (l *lane) SetWriteDeadline(t time.Time) error { return l.setDeadline(t, false, true) }

func (l *lane) wait(read bool) (packet, error) {
	for {
		s := l.s
		s.mx.Lock()
		deadline := l.write
		if read {
			deadline = l.read
		}
		changed := l.changed
		s.mx.Unlock()
		select {
		case <-l.closed:
			return packet{}, net.ErrClosed
		default:
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return packet{}, os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var in <-chan packet
		var slot chan<- struct{}
		if read {
			in = l.in
		} else {
			slot = s.writeSlot
		}
		var p packet
		var err error
		select {
		case p = <-in:
		case slot <- struct{}{}:
		case <-l.closed:
			err = net.ErrClosed
		case <-s.stopped:
			err = s.readErr
		case <-timeout:
			err = os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
		if timer != nil {
			timer.Stop()
		}
		return p, err
	}
}
func (l *lane) ReadFrom(dst []byte) (int, net.Addr, error) {
	p, e := l.wait(true)
	if e != nil {
		return 0, nil, e
	}
	return copy(dst, p.b), p.addr, nil
}
func (l *lane) WriteTo(b []byte, a net.Addr) (int, error) {
	_, err := l.wait(false)
	if err != nil {
		return 0, err
	}
	s := l.s
	defer func() { <-s.writeSlot }()
	s.mx.Lock()
	select {
	case <-l.closed:
		s.mx.Unlock()
		return 0, net.ErrClosed
	default:
	}
	s.writing = l
	if !l.write.IsZero() {
		err = s.SetWriteDeadline(l.write)
	}
	s.mx.Unlock()
	defer func() {
		s.mx.Lock()
		if !l.write.IsZero() || isClosed(l.closed) {
			_ = s.SetWriteDeadline(time.Time{})
		}
		s.writing = nil
		s.mx.Unlock()
	}()
	if err != nil {
		return 0, err
	}
	if l.framed {
		return sendFrame(s.PacketConn, b, a)
	}
	return s.PacketConn.WriteTo(b, a)
}
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
