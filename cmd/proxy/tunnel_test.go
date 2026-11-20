package main

import (
	"context"
	"crypto/ed25519"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/quic"
	"github.com/xssnick/tonutils-go/tl"
)

func TestTunnelAdvertisesExplicitQUICExit(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1)
	for _, port := range []uint16{12345, 65000} {
		addresses := tunnelAddresses(ip, port, true)
		if _, err := address.DialString(addresses[0]); err != nil {
			t.Fatal(err)
		}
		encoded, err := tl.Serialize(address.List{Addresses: addresses}, true)
		if err != nil {
			t.Fatal(err)
		}
		var decoded address.List
		if _, err := tl.Parse(&decoded, encoded, true); err != nil {
			t.Fatal(err)
		}
		endpoint, err := quic.PeerEndpoint(decoded.Addresses)
		if err != nil || endpoint.Port() != port || !endpoint.Addr().IsLoopback() {
			t.Fatalf("QUIC exit %v, %v; want tunnel port %d", endpoint, err, port)
		}
	}
	if len(tunnelAddresses(ip, 12345, false)) != 1 {
		t.Fatal("disabled QUIC was advertised")
	}
}

func TestTunnelExitAnnouncesNewEpochToConnectedPeer(t *testing.T) {
	open := func() (*adnl.Gateway, *net.UDPAddr) {
		t.Helper()
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		g := adnl.NewGatewayWithNetManager(key, adnl.NewSingleNetReader(func(string) (net.PacketConn, error) { return pc, nil }))
		t.Cleanup(func() { _ = g.Close() })
		addr := pc.LocalAddr().(*net.UDPAddr)
		g.SetAddressList(tunnelAddresses(addr.IP, uint16(addr.Port), true))
		if err = g.StartServer(addr.String(), 1); err != nil {
			t.Fatal(err)
		}
		return g, addr
	}
	server, a := open()
	client, _ := open()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := client.RegisterClient(a.String(), server.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	for peer.Stats().Channel.State != adnl.PeerChannelStateReady {
		if _, err = peer.Ping(ctx); err != nil {
			t.Fatal(err)
		}
	}
	oldEpoch := peer.Stats().Reinitialization.PeerEpoch
	if oldEpoch != server.GetAddressList().ReinitDate {
		t.Fatalf("peer has not learned initial epoch: %d", oldEpoch)
	}
	u := tunnelExitUpdates{tunnel: &tunnel.AtomicSwitchableRegularTunnel{}, changed: make(chan struct{}, 1)}
	oldTunnel, newTunnel := new(tunnel.RegularOutTunnel), new(tunnel.RegularOutTunnel)
	u.tunnel.SwitchTo(oldTunnel)
	u.update(oldTunnel, a)
	<-u.changed
	initial := u.address()
	done := make(chan struct{})
	go func() { defer close(done); u.announce(ctx, server, initial, true) }()
	defer func() { cancel(); <-done }()
	b := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: a.Port}
	u.tunnel.SwitchTo(newTunnel)
	u.update(newTunnel, b)
	u.update(oldTunnel, a) // A late callback from the retired exit must not restore A.
	// No client query here: it must learn the new epoch unsolicited, even if
	// both exits were selected in the same wall-clock second.
	for peer.Stats().Reinitialization.PeerEpoch <= oldEpoch {
		select {
		case <-ctx.Done():
			t.Fatal("peer never received the new exit epoch")
		case <-time.After(5 * time.Millisecond):
		}
	}
	list := server.GetAddressList()
	if u.address() != netip.AddrPortFrom(b.AddrPort().Addr().Unmap(), uint16(b.Port)) || list.Version <= oldEpoch || list.ReinitDate != peer.Stats().Reinitialization.PeerEpoch || len(list.Addresses) != 2 || !address.IPValue(list.Addresses[0]).Equal(b.IP) {
		t.Fatalf("unexpected published list: %+v; peer epoch %d", list, peer.Stats().Reinitialization.PeerEpoch)
	}
	u.update(newTunnel, b)
	select {
	case <-u.changed:
		t.Fatal("duplicate exit scheduled another reinitialization")
	default:
	}
}
