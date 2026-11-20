package quicwire

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// This vector is shared by the two independently built proxies.
func TestEnvelopeOnSharedSocket(t *testing.T) {
	listen := func() net.PacketConn {
		pc, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { pc.Close() })
		return pc
	}
	raw, remote := listen(), listen()
	native, framed := Split(raw)
	defer native.Close()
	defer framed.Close()
	deadline := time.Now().Add(2 * time.Second)
	for _, pc := range []net.PacketConn{native, framed, remote} {
		if e := pc.SetReadDeadline(deadline); e != nil {
			t.Fatal(e)
		}
	}
	payload := []byte{0x40, 1, 2, 3}
	vector := make([]byte, 64)
	copy(vector, []byte{0, 'T', 'Q', 'I', 'C', 1, 0, 4, 0x40, 1, 2, 3})
	write := func(pc net.PacketConn, b []byte, addr net.Addr) {
		t.Helper()
		n, e := pc.WriteTo(b, addr)
		if e != nil || n != len(b) {
			t.Fatalf("write %d/%d: %v", n, len(b), e)
		}
	}
	read := func(pc net.PacketConn, want []byte) net.Addr {
		t.Helper()
		buf := make([]byte, 2048)
		n, addr, e := pc.ReadFrom(buf)
		if e != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("read %x want %x: %v", buf[:n], want, e)
		}
		return addr
	}
	write(framed, payload, remote.LocalAddr())
	read(remote, vector)
	badLen := bytes.Clone(vector)
	badLen[7] = 70
	badPad := bytes.Clone(vector)
	badPad[63] = 1
	for _, bad := range [][]byte{vector[:63], badLen, badPad} {
		write(remote, bad, raw.LocalAddr())
	}
	write(remote, vector, raw.LocalAddr())
	write(remote, payload, raw.LocalAddr())
	read(framed, payload)
	read(native, payload)
	// Both packets use the same UDP source. Delaying the first reply must
	// not let the second packet switch its encoding.
	listener := Accept(remote)
	write(framed, payload, listener.LocalAddr())
	framedPeer := read(listener, payload)
	write(native, payload, listener.LocalAddr())
	nativePeer := read(listener, payload)
	write(listener, payload, nativePeer)
	read(native, payload)
	if err := native.Close(); err != nil {
		t.Fatal(err)
	}
	write(listener, payload, framedPeer)
	read(framed, payload)
}
