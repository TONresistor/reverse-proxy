package rldphttp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/xssnick/tonutils-go/adnl/quic"
)

func (s *Server) capabilities() int64 {
	s.mx.RLock()
	defer s.mx.RUnlock()
	if s.quicServer != nil {
		return CapabilityRLDP2 | CapabilityQUIC
	}
	return CapabilityRLDP2
}

func (s *Server) startQUIC(listenAddr string) error {
	host, portText, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 64535 {
		return fmt.Errorf("ADNL port must be between 1 and 64535 when QUIC is enabled")
	}
	gate, err := quic.NewGateway(s.key)
	if err != nil {
		return err
	}
	gate.SetConnectionHandler(func(peer *quic.Peer) error {
		id, err := SerializeADNLAddress(peer.PeerID())
		if err != nil {
			return err
		}
		client := &quicClient{peer: peer}
		client.SetOnQuery(s.handle(client, id, peer.RemoteAddr()))
		return nil
	})
	socket, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(port+1000)))
	if err != nil {
		_ = gate.Close()
		return fmt.Errorf("listen QUIC: %w", err)
	}
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		_ = socket.Close()
		_ = gate.Close()
		return ErrServerStopped
	}
	s.quicServer = gate
	s.mx.Unlock()
	go func() {
		defer socket.Close()
		if err := gate.Serve(socket); err != nil {
			s.mx.RLock()
			closed := s.closed
			s.mx.RUnlock()
			if !closed {
				Logger("QUIC server stopped: ", err)
				_ = s.Stop()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := gate.WaitReady(ctx); err != nil {
		return fmt.Errorf("start QUIC: %w", err)
	}
	Logger("QUIC HTTP listening on ", socket.LocalAddr())
	return nil
}
