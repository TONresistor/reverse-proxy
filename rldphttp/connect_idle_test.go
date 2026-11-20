package rldphttp

import (
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestConnectIdlePartsPrecedeRLDPDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, origin := net.Pipe()
		defer conn.Close()
		defer origin.Close()
		stream := &payloadStream{Data: tunnelReader{conn}}
		started := time.Now()
		for seq := int32(0); seq < 4; seq++ {
			poll := time.Now()
			part, err := handleGetPart(GetNextPayloadPart{Seqno: seq, MaxChunkSize: 1024}, stream)
			if err != nil || len(part.Data) != 0 || part.IsLast {
				t.Fatalf("idle part = %+v, err = %v", part, err)
			}
			if elapsed := time.Since(poll); elapsed >= 15*time.Second {
				t.Fatalf("idle part took %v, exceeding the RLDP query deadline", elapsed)
			}
		}
		if time.Since(started) <= 15*time.Second {
			t.Fatal("test did not keep the idle stream beyond one RLDP query deadline")
		}
		written := make(chan error, 1)
		go func() { _, err := origin.Write([]byte("resumed")); written <- err }()
		part, err := handleGetPart(GetNextPayloadPart{Seqno: 4, MaxChunkSize: 1024}, stream)
		if err != nil || string(part.Data) != "resumed" || part.IsLast {
			t.Fatalf("resumed part = %+v, err = %v", part, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	})
}
