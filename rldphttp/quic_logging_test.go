package rldphttp

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
)

type quicLogCapture chan map[string]any

func (c quicLogCapture) Write(data []byte) (int, error) {
	var event map[string]any
	if err := json.Unmarshal(data, &event); err != nil {
		return 0, err
	}
	select {
	case c <- event:
	default:
	}
	return len(data), nil
}

func (c quicLogCapture) wait(t *testing.T, message string) map[string]any {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-c:
			if event["message"] == message {
				return event
			}
		case <-timer.C:
			t.Fatalf("missing QUIC log %q", message)
		}
	}
}

func TestQUICLogsWithoutDebug(t *testing.T) {
	// Match the CLI's normal mode: legacy RLDP logging is disabled.
	previousLogger, previousQUICLogger := Logger, log.Logger
	Logger = func(...any) {}
	events := make(quicLogCapture, 16)
	log.Logger = zerolog.New(events).Level(zerolog.InfoLevel)
	t.Cleanup(func() {
		Logger, log.Logger = previousLogger, previousQUICLogger
	})

	t.Run("bound address and socket failure", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		srv := NewServer(key, nil, nil, http.NotFoundHandler())
		defer srv.Stop()
		srv.QUICPacketConn = conn
		if err := srv.startQUIC(""); err != nil {
			t.Fatal(err)
		}
		event := events.wait(t, "QUIC HTTP listening")
		if event["level"] != "info" || event["address"] != conn.LocalAddr().String() {
			t.Fatalf("unexpected startup log: %v", event)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		event = events.wait(t, "QUIC stopped, continuing with RLDP2")
		if event["level"] != "warn" || event["error"] == nil {
			t.Fatalf("unexpected runtime failure log: %v", event)
		}
		if srv.capabilitiesFor(0) != CapabilityRLDP2 {
			t.Fatal("QUIC still advertised after socket failure")
		}
	})

	t.Run("busy port", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		var rldpConn, busyQUIC net.PacketConn
		for attempt := 0; attempt < 20; attempt++ {
			rldpConn, err = net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			bind := rldpConn.LocalAddr().(*net.UDPAddr)
			if bind.Port <= 64535 {
				busyQUIC, err = net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(bind.Port+1000)))
				if err == nil {
					break
				}
			}
			_ = rldpConn.Close()
		}
		if busyQUIC == nil {
			t.Fatal("failed to reserve QUIC port")
		}
		defer busyQUIC.Close()
		defer rldpConn.Close()
		manager := adnl.NewMultiNetReader(rldpConn)
		defer manager.Close()
		gate := adnl.NewGatewayWithNetManager(key, manager)
		bind := rldpConn.LocalAddr().(*net.UDPAddr)
		gate.SetAddressList([]address.Address{&address.UDP{IP: bind.IP, Port: int32(bind.Port)}})
		srv := NewServer(key, gate, quicTestDHT{}, http.NotFoundHandler())
		done := make(chan error, 1)
		go func() { done <- srv.ListenAndServe(rldpConn.LocalAddr().String()) }()
		t.Cleanup(func() {
			if err := srv.Stop(); err != nil {
				t.Error(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("server did not stop")
			}
		})
		event := events.wait(t, "Failed to start QUIC, continuing with RLDP2")
		if event["level"] != "warn" || !strings.Contains(fmt.Sprint(event["error"]), "failed to bind QUIC socket") {
			t.Fatalf("unexpected startup failure log: %v", event)
		}
		if srv.capabilitiesFor(0) != CapabilityRLDP2 {
			t.Fatal("unavailable QUIC advertised")
		}
		select {
		case err := <-done:
			t.Fatalf("RLDP server stopped after QUIC bind failure: %v", err)
		default:
		}
	})
}
