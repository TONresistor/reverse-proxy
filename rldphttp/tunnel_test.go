package rldphttp

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
)

func testTunnel(t *testing.T, ctx context.Context) (net.PacketConn, *net.UDPAddr) {
	t.Helper()
	type node struct {
		key  ed25519.PublicKey
		gate *adnl.Gateway
		tun  *tunnel.Gateway
		addr net.Addr
	}
	logger := zerolog.New(io.Discard)
	nodes := make([]node, 2)
	for i := range nodes {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		manager := adnl.NewMultiNetReader(socket)
		gate := adnl.NewGatewayWithNetManager(key, manager)
		if err := gate.StartServer(socket.LocalAddr().String(), 1); err != nil {
			t.Fatal(err)
		}
		addr := socket.LocalAddr().(*net.UDPAddr)
		gate.SetAddressList([]address.Address{&address.UDP{IP: addr.IP, Port: int32(addr.Port)}})
		tg := tunnel.NewGateway(gate, nil, key, logger, tunnel.PaymentConfig{})
		nodes[i] = node{key.Public().(ed25519.PublicKey), gate, tg, addr}
		done := make(chan error, 1)
		go func() { done <- tg.Start() }()
		t.Cleanup(func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = tg.Stop(stopCtx)
			_ = gate.Close()
			manager.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-stopCtx.Done():
				t.Error("tunnel node did not stop")
			}
		})
	}
	// Start installs handlers before CreateRegularOutTunnel sends its first packet.
	// Registering peers afterwards also lets Start bootstrap either ordering.
	if _, err := nodes[0].gate.RegisterClient(nodes[1].addr.String(), nodes[1].key); err != nil {
		t.Fatal(err)
	}
	sections := make([]*tunnel.SectionInfo, 2)
	for i := range nodes {
		keys, err := tunnel.GenerateEncryptionKeys(nodes[i].key)
		if err != nil {
			t.Fatal(err)
		}
		sections[i] = &tunnel.SectionInfo{Keys: keys}
	}
	tun, err := nodes[0].tun.CreateRegularOutTunnel(ctx, []*tunnel.SectionInfo{sections[1]}, []*tunnel.SectionInfo{sections[0]}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tun.Stop(stopCtx)
	})
	ip, port, err := tun.WaitForInit(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tun, &net.UDPAddr{IP: ip, Port: int(port)}
}
