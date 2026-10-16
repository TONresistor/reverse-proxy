package rldphttp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
)

// RLDP query metadata stays local; QUIC carries only boxed HTTP TL objects.
type quicClient struct {
	peer    *quic.Peer
	pending sync.Map
}

type quicReply struct {
	ctx    context.Context
	answer chan []byte
}

func (c *quicClient) Close()             { _ = c.peer.Close() }
func (c *quicClient) GetADNL() rldp.ADNL { return nil }

func (c *quicClient) SetOnDisconnect(handler func()) {
	c.peer.SetDisconnectHandler(func(*quic.Peer) { handler() })
}

func (c *quicClient) DoQuery(ctx context.Context, maxAnswerSize uint64, query, result tl.Serializable) error {
	data, err := tl.Serialize(query, true)
	if err != nil {
		return err
	}
	if maxAnswerSize == 0 || maxAnswerSize > quic.DefaultMaxObjectSize-16 {
		return errors.New("invalid QUIC HTTP answer size")
	}
	answer, err := c.peer.Query(ctx, data, int64(maxAnswerSize))
	if err != nil {
		return err
	}
	rest, err := tl.Parse(result, answer, true)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing bytes in QUIC HTTP answer")
	}
	return nil
}

func (c *quicClient) SetOnQuery(handler func([]byte, *rldp.Query) error) {
	c.peer.SetQueryHandler(func(ctx context.Context, payload []byte) ([]byte, error) {
		var data any
		rest, err := tl.Parse(&data, payload, true)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("trailing bytes in QUIC HTTP query")
		}
		timeout := 30 * time.Second
		if _, ok := data.(GetNextPayloadPart); ok {
			timeout = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		id := make([]byte, 32)
		if _, err = rand.Read(id); err != nil {
			return nil, err
		}
		reply := &quicReply{ctx: ctx, answer: make(chan []byte, 1)}
		c.pending.Store(string(id), reply)
		defer c.pending.Delete(string(id))
		deadline, _ := ctx.Deadline()
		query := &rldp.Query{ID: id, MaxAnswerSize: quic.DefaultMaxObjectSize - 16,
			Timeout: uint32(deadline.Unix()), Data: data}
		if err = handler(nil, query); err != nil {
			return nil, err
		}
		select {
		case answer := <-reply.answer:
			return answer, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
}

func (c *quicClient) SendAnswer(ctx context.Context, maxAnswerSize uint64, _ uint32, queryID, _ []byte, answer tl.Serializable) error {
	value, ok := c.pending.LoadAndDelete(string(queryID))
	if !ok {
		return errors.New("QUIC HTTP query is no longer pending")
	}
	reply := value.(*quicReply)
	data, err := tl.Serialize(answer, true)
	if err != nil {
		return err
	}
	if uint64(len(data)) > maxAnswerSize {
		return fmt.Errorf("QUIC HTTP answer exceeds %d bytes", maxAnswerSize)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-reply.ctx.Done():
		return reply.ctx.Err()
	case reply.answer <- data:
		return nil
	}
}
