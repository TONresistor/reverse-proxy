package rldphttp

import (
	"bytes"
	"encoding/hex"
	"slices"
	"time"
)

// A request ID belongs to the authenticated ADNL identity, across transports.
func payloadKey(peer string, id []byte) string { return peer + ":" + hex.EncodeToString(id) }

type savedPart struct {
	key       string
	seq, size int32
	until     time.Time
	part      *PayloadPart
}

func (sh *activeRequestShard) forgetPart(key string) {
	sh.recent = slices.DeleteFunc(sh.recent, func(p savedPart) bool { return p.key == key })
}

func (sh *activeRequestShard) expireParts(now time.Time) {
	sh.recent = slices.DeleteFunc(sh.recent, func(p savedPart) bool { return !now.Before(p.until) })
}

func (sh *activeRequestShard) findPart(key string, req GetNextPayloadPart, now time.Time) *PayloadPart {
	for _, p := range sh.recent {
		if p.key == key && p.seq == req.Seqno && p.size == req.MaxChunkSize && now.Before(p.until) {
			return p.part
		}
	}
	return nil
}

// Store before making the answer visible on the wire. Reading consumes the
// origin stream even if the sending peer never receives the answer.
func (r *activeRequestRegistry) rememberPart(key string, req GetNextPayloadPart, stream *payloadStream, part *PayloadPart, ttl time.Duration) {
	sh := r.shard(key)
	if len(part.Data) < cap(part.Data) {
		part.Data = bytes.Clone(part.Data)
	}
	sh.mx.Lock()
	defer sh.mx.Unlock()
	if sh.streams[key] != stream {
		return
	}
	sh.forgetPart(key)
	// At most 16 entries and 1 MiB of payload per shard (64 MiB total).
	total := len(part.Data)
	for _, p := range sh.recent {
		total += len(p.part.Data)
	}
	for len(sh.recent) > 0 && (len(sh.recent) >= 16 || total > 1<<20) {
		total -= len(sh.recent[0].part.Data)
		sh.recent = slices.Delete(sh.recent, 0, 1)
	}
	sh.recent = append(sh.recent, savedPart{key, req.Seqno, req.MaxChunkSize, time.Now().Add(min(ttl, 30*time.Second)), part})
}
