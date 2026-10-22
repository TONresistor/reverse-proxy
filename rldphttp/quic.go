package rldphttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

const quicMaxObjectSize = 4 << 20

func newQUICGateway(key ed25519.PrivateKey) (*quic.Gateway, error) {
	limits := quic.DefaultLimits()
	limits.MaxObjectSize = quicMaxObjectSize
	return quic.NewGatewayWithLimits(limits, key)
}

// quicClient bridges stream-scoped QUIC answers to the asynchronous RLDP interface.
// Query IDs exist only locally; the wire carries boxed http.* objects directly.
type quicClient struct {
	peer         *quic.Peer
	mx           sync.Mutex
	onQuery      func([]byte, *rldp.Query) error
	onDisconnect func()
	pending      map[string]chan quicResult
	queryTimeout time.Duration
	closed       bool
	done         chan struct{}
}

type quicResult struct {
	data []byte
	err  error
}

var _ RLDP = (*quicClient)(nil)

func newQUICClient(peer *quic.Peer, timeout time.Duration) *quicClient {
	c := &quicClient{peer: peer, pending: make(map[string]chan quicResult), done: make(chan struct{}), queryTimeout: timeout}
	peer.SetQueryHandler(c.handleQuery)
	peer.SetDisconnectHandler(func(*quic.Peer) { c.disconnect() })
	return c
}

func (c *quicClient) Close() {
	c.disconnect()
	if err := c.peer.Close(); err != nil {
		Logger("failed to close QUIC peer:", err)
	}
}

func (c *quicClient) disconnect() {
	c.mx.Lock()
	if c.closed {
		c.mx.Unlock()
		return
	}
	c.closed = true
	clear(c.pending)
	close(c.done)
	handler := c.onDisconnect
	c.onQuery = nil
	c.onDisconnect = nil
	c.mx.Unlock()
	if handler != nil {
		handler()
	}
}

func (c *quicClient) SetOnDisconnect(handler func()) {
	c.mx.Lock()
	if c.closed {
		c.mx.Unlock()
		if handler != nil {
			handler()
		}
		return
	}
	c.onDisconnect = handler
	c.mx.Unlock()
}

func (c *quicClient) SetOnQuery(handler func([]byte, *rldp.Query) error) {
	c.mx.Lock()
	defer c.mx.Unlock()
	if !c.closed {
		c.onQuery = handler
	}
}

func parseQUICHTTP(data []byte) (obj tl.Serializable, err error) {
	// Keep malformed network data from escaping the transport callback as a panic.
	defer func() {
		if r := recover(); r != nil {
			obj = nil
			err = fmt.Errorf("failed to parse QUIC HTTP object: %v", r)
		}
	}()
	rest, err := tl.Parse(&obj, data, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse QUIC HTTP object: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected trailing QUIC HTTP data")
	}
	switch obj.(type) {
	case Request, GetNextPayloadPart, Response, PayloadPart:
		return obj, nil
	default:
		return nil, fmt.Errorf("unexpected QUIC HTTP object %T", obj)
	}
}

func (c *quicClient) DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error {
	switch query.(type) {
	case Request, *Request, GetNextPayloadPart, *GetNextPayloadPart:
	default:
		return fmt.Errorf("unexpected QUIC HTTP query %T", query)
	}
	data, err := tl.Serialize(query, true)
	if err != nil {
		return fmt.Errorf("failed to serialize QUIC HTTP query: %w", err)
	}
	answer, err := c.peer.Query(ctx, data, int64(min(maxAnswerSize, uint64(quic.DefaultMaxObjectSize))))
	if err != nil {
		return fmt.Errorf("failed to query QUIC HTTP peer: %w", err)
	}
	obj, err := parseQUICHTTP(answer)
	if err != nil {
		return err
	}
	switch obj.(type) {
	case Response, PayloadPart:
	default:
		return fmt.Errorf("unexpected QUIC HTTP answer %T", obj)
	}
	destination := reflect.ValueOf(result)
	if !destination.IsValid() || destination.Kind() != reflect.Pointer || destination.IsNil() {
		return fmt.Errorf("QUIC HTTP result must be a non-nil pointer")
	}
	value := reflect.ValueOf(obj)
	if !value.Type().AssignableTo(destination.Elem().Type()) {
		return fmt.Errorf("unexpected QUIC HTTP answer %T for %T", obj, result)
	}
	destination.Elem().Set(value)
	return nil
}

func (c *quicClient) handleQuery(ctx context.Context, data []byte) (_ []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	obj, err := parseQUICHTTP(data)
	if err != nil {
		return nil, err
	}
	switch obj.(type) {
	case Request, GetNextPayloadPart:
	default:
		return nil, fmt.Errorf("unexpected QUIC HTTP query %T", obj)
	}
	id := make([]byte, 32)
	if _, err = rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate QUIC query id: %w", err)
	}
	answer := make(chan quicResult, 1)
	c.mx.Lock()
	if c.closed || c.onQuery == nil {
		c.mx.Unlock()
		return nil, fmt.Errorf("QUIC HTTP query handler is unavailable")
	}
	handler := c.onQuery
	c.pending[string(id)] = answer
	c.mx.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic while handling QUIC HTTP query: %v", recovered)
			c.failQuery(id, err)
		}
		c.mx.Lock()
		delete(c.pending, string(id))
		c.mx.Unlock()
	}()

	// IDs are local to this stream. QUIC carries no RLDP transfer ID.
	deadline, _ := ctx.Deadline()
	if err = handler(nil, &rldp.Query{ID: id, MaxAnswerSize: quic.DefaultMaxObjectSize, Timeout: uint32(deadline.Unix()), Data: obj}); err != nil {
		c.failQuery(id, err)
		return nil, err
	}

	select {
	case result := <-answer:
		return result.data, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, quic.ErrPeerClosed
	}
}

func (c *quicClient) SendAnswer(ctx context.Context, _ uint64, _ uint32, queryId, _ []byte, answer tl.Serializable) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch answer.(type) {
	case Response, *Response, PayloadPart, *PayloadPart:
	default:
		return fmt.Errorf("unexpected QUIC HTTP answer %T", answer)
	}
	data, err := tl.Serialize(answer, true)
	if err != nil {
		return fmt.Errorf("failed to serialize QUIC HTTP answer: %w", err)
	}
	c.mx.Lock()
	defer c.mx.Unlock()
	pending := c.pending[string(queryId)]
	if pending == nil {
		return fmt.Errorf("unknown QUIC HTTP query id")
	}
	select {
	case pending <- quicResult{data: data}:
		delete(c.pending, string(queryId))
		return nil
	default:
		return fmt.Errorf("QUIC HTTP query already answered")
	}
}

// failQuery releases a stream whose asynchronous HTTP handler could not answer.
func (c *quicClient) failQuery(id []byte, err error) {
	c.mx.Lock()
	defer c.mx.Unlock()
	if pending := c.pending[string(id)]; pending != nil {
		pending <- quicResult{err: err}
		delete(c.pending, string(id))
	}
}
