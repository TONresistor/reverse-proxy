package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mdp/qrterminal/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sigurn/crc16"
	tunnelConfig "github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/ton-utils/reverse-proxy/config"
	"github.com/ton-utils/reverse-proxy/internal/quicwire"
	"github.com/ton-utils/reverse-proxy/rldphttp"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"io"
	regularLog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	ConnectPorts                 []uint16                  `json:"connect_ports,omitempty"`
	ProxyPass                    string                    `json:"proxy_pass"`
	PrivateKey                   []byte                    `json:"private_key"`
	ExternalIP                   string                    `json:"external_ip"`
	ListenIP                     string                    `json:"listen_ip"`
	NetworkConfigURL             string                    `json:"network_config_url"`
	CustomTunnelNetworkConfigURL string                    `json:"custom_tunnel_network_config_url"`
	Port                         uint16                    `json:"port"`
	TunnelConfig                 tunnelConfig.ClientConfig `json:"tunnel_config"`
	Version                      int                       `json:"version"`
}

var FlagQUIC = flag.Bool("quic", true, "accept TON QUIC (direct UDP or through the configured tunnel)")

var FlagDomain = flag.String("domain", "", "domain to configure")
var FlagDebug = flag.Bool("debug", false, "more logs")
var FlagAllowInsecureHttps = flag.Bool("allow-insecure-https", false, "allow insecure https")
var FlagTxURL = flag.Bool("tx-url", false, "show set domain record url instead of qr")
var EnableTunnel = flag.Bool("enable-tunnel", false, "enable tunnel mode, to host site with no public ip (should be configured first)")
var FlagMaxConcurrentRequests = flag.Int(
	"max-concurrent-requests",
	rldphttp.DefaultMaxConcurrentRequests,
	"maximum number of concurrent RLDP HTTP requests across all peers",
)

var GitCommit = "dev"

const reverseProxyFlushInterval = 20 * time.Millisecond

func envOrVal(env string, arg any) any {
	var res = arg

	val, exists := os.LookupEnv(env)
	if exists && val != "" {
		switch arg.(type) {
		case []byte:
			v, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				panic(err.Error())
			}
			return v
		case uint16:
			v, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				panic(err.Error())
			}
			return uint16(v)
		case string:
			return val
		case bool:
			ok := strings.ToLower(val) != "0" && strings.ToLower(val) != "false"
			return ok
		}
	}

	return res
}

type Handler struct {
	h http.Handler
}

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if *FlagDebug {
		reqDump, err := httputil.DumpRequestOut(request, true)
		if err != nil {
			return
		}
		log.Debug().
			Str("request_dump", string(reqDump)).
			Msg("Dumping HTTP request")
	}

	hdr := http.Header{}
	for k := range request.Header {
		// make headers canonical
		for _, s := range request.Header.Values(k) {
			hdr.Add(k, s)
		}
	}
	request.Header = hdr

	log.Debug().
		Str("method", request.Method).
		Str("host", request.Host).
		Str("uri", request.RequestURI).
		Msg("Received HTTP request")

	writer.Header().Set("Ton-Reverse-Proxy", "Tonutils Reverse Proxy "+GitCommit)
	h.h.ServeHTTP(writer, request)
}

func main() {
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if *FlagDebug {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}
	if *FlagMaxConcurrentRequests <= 0 {
		log.Fatal().Int("max_concurrent_requests", *FlagMaxConcurrentRequests).
			Msg("max-concurrent-requests must be greater than zero")
	}

	log.Info().Str("version", GitCommit).Msg("Starting Tonutils Reverse Proxy")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	netCfg, err := liteclient.GetConfigFromUrl(context.Background(), cfg.NetworkConfigURL)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to download TON config, using static cache")
		netCfg = &liteclient.GlobalConfig{}
		if err = json.NewDecoder(bytes.NewBufferString(config.FallbackNetworkConfig)).Decode(netCfg); err != nil {
			log.Fatal().Err(err).Msg("Failed to parse fallback TON config")
		}
	}

	client := liteclient.NewConnectionPool()

	closerCtx, stop := context.WithCancel(context.Background())
	defer stop()

	ctx, cancel := context.WithTimeout(closerCtx, 30*time.Second)
	defer cancel()

	err = client.AddConnectionsFromConfig(ctx, netCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add connections from config")
	}

	tunnelCtx, tunnelStop := context.WithCancel(context.Background())

	port := cfg.Port
	ip := net.ParseIP(cfg.ExternalIP)

	var netMgr adnl.NetManager
	var quicConn net.PacketConn
	var gate *adnl.Gateway
	if *EnableTunnel {
		tunNetCfg := netCfg
		if cfg.CustomTunnelNetworkConfigURL != "" {
			log.Info().Str("url", cfg.CustomTunnelNetworkConfigURL).Msg("Using custom tunnel network config")
			tunNetCfg, err = liteclient.GetConfigFromUrl(context.Background(), cfg.CustomTunnelNetworkConfigURL)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to download custom tunnel network config")
				return
			}
		}

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
		if *FlagDebug {
			log.Logger = log.Logger.Level(zerolog.DebugLevel)
		}

		if cfg.TunnelConfig.NodesPoolConfigPath == "" {
			log.Fatal().Msg("Nodes pool config path is empty")
			return
		}

		data, err := os.ReadFile(cfg.TunnelConfig.NodesPoolConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load tunnel nodes pool config")
			return
		}

		var tunSharedCfg tunnelConfig.SharedConfig
		if err = json.Unmarshal(data, &tunSharedCfg); err != nil {
			log.Fatal().Err(err).Msg("Failed to parse tunnel shared config (nodes pool)")
			return
		}

		events := make(chan any, 1)
		go tunnel.RunTunnel(closerCtx, &cfg.TunnelConfig, &tunSharedCfg, tunNetCfg, log.Logger, events)

		atm := &tunnel.AtomicSwitchableRegularTunnel{}
		exits := tunnelExitUpdates{tunnel: atm, changed: make(chan struct{}, 1)}
		go func() {
			for event := range events {
				switch e := event.(type) {
				case tunnel.StoppedEvent:
					tunnelStop()
					return
				case tunnel.UpdatedEvent:
					log.Info().Msg("Tunnel updated")

					tun := e.Tunnel
					atm.SwitchTo(tun)
					exits.update(tun, &net.UDPAddr{IP: e.ExtIP, Port: int(e.ExtPort)})
					tun.SetOutAddressChangedHandler(func(addr *net.UDPAddr) { exits.update(tun, addr) })
				case tunnel.ConfigurationErrorEvent:
					log.Err(e.Err).Msg("Tunnel configuration error, will retry...")
				case error:
					log.Fatal().Err(e).Msg("Tunnel failed")
				}
			}
		}()

		select {
		case <-exits.changed:
		case <-tunnelCtx.Done():
			return
		}
		initial := exits.address()
		ip, port = net.IP(initial.Addr().AsSlice()), initial.Port()
		var ad net.PacketConn = atm
		if *FlagQUIC {
			ad, quicConn = quicwire.Split(atm)
			defer quicConn.Close()
		}
		manager := adnl.NewMultiNetReader(ad)
		netMgr = manager
		gate = adnl.NewGatewayWithNetManager(ed25519.NewKeyFromSeed(cfg.PrivateKey), netMgr)
		gate.SetAddressList(tunnelAddresses(ip, port, *FlagQUIC))
		go exits.announce(tunnelCtx, gate, initial, *FlagQUIC)
		log.Info().Msg("Using tunnel")
	} else {
		addr := cfg.ListenIP + ":" + strconv.Itoa(int(cfg.Port))
		dl, err := adnl.DefaultListener(addr)
		if err != nil {
			log.Fatal().Err(err).Str("addr", addr).Msg("Failed to create listener")
			return
		}
		netMgr = adnl.NewMultiNetReader(dl)
		gate = adnl.NewGatewayWithNetManager(ed25519.NewKeyFromSeed(cfg.PrivateKey), netMgr)
	}

	adnlAddr, err := address.NewAddress(ip, int32(port))
	if err != nil {
		log.Fatal().Err(err).Str("ip", cfg.ExternalIP).Uint16("port", port).Msg("Failed to build ADNL address")
	}
	if !*EnableTunnel {
		gate.SetAddressList([]address.Address{adnlAddr})
	}

	_, dhtAdnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate key for DHT")
	}

	dhtGateway := adnl.NewGatewayWithNetManager(dhtAdnlKey, netMgr)
	err = dhtGateway.StartClient()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start ADNL gateway client")
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGateway, netCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create DHT client from config")
	}

	u, err := url.Parse(cfg.ProxyPass)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse proxy pass URL")
	}

	if *FlagDebug == false {
		adnl.Logger = func(v ...any) {}
		rldphttp.Logger = func(v ...any) {}
	} else {
		rldp.Logger = regularLog.Println
		rldphttp.Logger = regularLog.Println
		// adnl.Logger = regularLog.Println
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = reverseProxyFlushInterval
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: *FlagAllowInsecureHttps}}

	proxy.ModifyResponse = func(resp *http.Response) error {
		for _, c := range resp.Header["Set-Cookie"] {
			name := "<malformed>"
			if idx := strings.IndexByte(c, '='); idx > 0 {
				name = c[:idx]
			}
			log.Warn().Str("url", resp.Request.URL.String()).Int("code", resp.StatusCode).Str("set_cookie_name", name).Msg("Upstream Set-Cookie")
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			log.Debug().Str("redirect", loc).Msg("Upstream redirect preserved")
		}
		return nil
	}

	s, err := rldphttp.NewServerWithMaxConcurrentRequests(
		ed25519.NewKeyFromSeed(cfg.PrivateKey),
		gate,
		dhtClient,
		Handler{proxy},
		*FlagMaxConcurrentRequests,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to configure RLDP HTTP server")
	}

	s.EnableQUIC = *FlagQUIC
	if quicConn != nil {
		s.UseQUICTunnel(quicConn)
	}
	s.ConnectDialContext = rldphttp.DialConnectTo(u.Hostname(), cfg.ConnectPorts...)

	addr, err := rldphttp.SerializeADNLAddress(s.Address())
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to serialize ADNL address")
	}
	log.Info().Str("ADNL_address", addr).Str("hex_address", hex.EncodeToString(s.Address())).Msg("Server's ADNL address")

	if *FlagDomain != "" {
		setupDomain(client, *FlagDomain, s.Address())
	}

	go func() {
		log.Info().Str("address", addr+".adnl").
			Int("max_concurrent_requests", *FlagMaxConcurrentRequests).
			Msg("Starting server")
		if err = s.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.Port)); err != nil {
			log.Fatal().Err(err).Msg("Failed to listen and serve")
		}
	}()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan

	stop()

	log.Info().Msg("Received stop signal, shutting down...")
	if *EnableTunnel {
		log.Info().Msg("Stopping tunnel...")
		<-tunnelCtx.Done()
	}

	log.Info().Msg("Server stopped")
}

func getPublicIP() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("public ip service returned %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}

	var ip struct {
		IP    string `json:"ip"`
		Query string
	}
	err = json.Unmarshal(body, &ip)
	if err != nil {
		return "", err
	}

	if ip.IP == "" {
		ip.IP = ip.Query
	}
	if net.ParseIP(ip.IP) == nil {
		return "", fmt.Errorf("public ip service returned invalid ip `%s`", ip.IP)
	}

	return ip.IP, nil
}

func loadConfig() (*Config, error) {
	var cfg Config

	save := false
	file := "./config.json"
	data, err := os.ReadFile(file)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		var srvKey ed25519.PrivateKey
		_, srvKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		cfg.Version = 1
		cfg.PrivateKey = srvKey.Seed()
		cfg.NetworkConfigURL = "https://ton-blockchain.github.io/global.config.json"

		cfg.ExternalIP, err = getPublicIP()
		if err != nil {
			return nil, fmt.Errorf("failed to get public ip: %w", err)
		}
		cfg.ListenIP = "0.0.0.0"

		// generate consistent port
		cfg.Port = 9000 + (crc16.Checksum([]byte(cfg.ExternalIP), crc16.MakeTable(crc16.CRC16_XMODEM)) % 5000)

		cfg.ProxyPass = "http://127.0.0.1:80/"
		tc, err := tunnelConfig.GenerateClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to generate tunnel config: %w", err)
		}

		cfg.TunnelConfig = *tc
		save = true
	} else {
		err = json.Unmarshal(data, &cfg)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Version < 1 {
		tc, err := tunnelConfig.GenerateClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to generate tunnel config: %w", err)
		}
		cfg.Version = 1
		cfg.TunnelConfig = *tc

		if cfg.NetworkConfigURL == "" {
			cfg.NetworkConfigURL = "https://ton-blockchain.github.io/global.config.json"
		}
		save = true
	}

	if save {
		data, err = json.MarshalIndent(cfg, "", "\t")
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(file, data, 0600) // rw-------
		if err != nil {
			return nil, err
		}
	}

	cfg.ExternalIP = envOrVal("EXTERNAL_IP", cfg.ExternalIP).(string)
	cfg.ListenIP = envOrVal("LISTEN_IP", cfg.ListenIP).(string)
	cfg.Port = envOrVal("LISTEN_PORT", cfg.Port).(uint16)
	cfg.ProxyPass = envOrVal("PROXY_PASS", cfg.ProxyPass).(string)
	cfg.PrivateKey = envOrVal("PRIVATE_KEY", cfg.PrivateKey).([]byte)
	cfg.NetworkConfigURL = envOrVal("NETWORK_CONFIG_URL", cfg.NetworkConfigURL).(string)
	if len(cfg.PrivateKey) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key seed should be %d bytes, got %d", ed25519.SeedSize, len(cfg.PrivateKey))
	}

	return &cfg, nil
}

func setupDomain(client *liteclient.ConnectionPool, domain string, adnlAddr []byte) {
	ctx := client.StickyContext(context.Background())
	// initialize ton api lite connection wrapper
	api := ton.NewAPIClient(client)

	// get root dns address from network config
	root, err := dns.GetRootContractAddr(ctx, api)
	if err != nil {
		log.Error().Err(err).Msg("Failed to resolve root dns contract")
		return
	}

	resolver := dns.NewDNSClient(api, root)
	domainInfo, err := resolver.Resolve(ctx, domain)
	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("Failed to configure domain")
		return
	}

	record, isStorage := domainInfo.GetSiteRecord()
	if isStorage || !bytes.Equal(record, adnlAddr) {
		data := domainInfo.BuildSetSiteRecordPayload(adnlAddr, false).ToBOCWithFlags(false)
		args := "?bin=" + base64.URLEncoding.EncodeToString(data) + "&amount=" + tlb.MustFromTON("0.02").Nano().String()

		nftData, err := domainInfo.GetNFTData(ctx)
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("Failed to get domain data")
			return
		}

		txUrl := "ton://transfer/" + domainInfo.GetNFTAddress().String() + args
		if *FlagTxURL {
			fmt.Println(txUrl)
		} else {
			qrterminal.GenerateHalfBlock(txUrl, qrterminal.L, os.Stdout)
		}
		fmt.Println("Execute this transaction from the domain owner's wallet to setup site records.")
		fmt.Println("Execute transaction from wallet:", nftData.OwnerAddress.String())
		fmt.Println("When you've done, configuration will automatically proceed in ~10 seconds.")
		for {
			time.Sleep(2 * time.Second)
			updated, err := resolve(ctx, resolver, domain, adnlAddr)
			if err != nil {
				log.Warn().Err(err).Str("domain", domain).Msg("Retrying domain resolution")
				continue
			}

			if updated {
				break
			}
		}
		log.Info().Str("domain", domain).Msg("Domain successfully configured to use for your TON Site")
		return
	}

	log.Info().Str("domain", domain).Msg("Domain is already configured to use with current ADNL address. Everything is OK!")
}

func resolve(ctx context.Context, client *dns.Client, domain string, adnlAddr []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	domainInfo, err := client.Resolve(ctx, domain)
	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("Failed to resolve domain")
		return false, err
	}

	record, isStorage := domainInfo.GetSiteRecord()
	if isStorage {
		return false, nil
	}

	return bytes.Equal(record, adnlAddr), nil
}

// Address callbacks can run under the tunnel's lock. Only the publisher sends packets.
type tunnelExitUpdates struct {
	tunnel  *tunnel.AtomicSwitchableRegularTunnel
	mx      sync.Mutex
	latest  netip.AddrPort
	changed chan struct{}
}

func (u *tunnelExitUpdates) update(source *tunnel.RegularOutTunnel, addr *net.UDPAddr) {
	u.mx.Lock()
	defer u.mx.Unlock()
	ep := addr.AddrPort()
	ep = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
	if source != u.tunnel.Current() || ep == u.latest {
		return
	}
	u.latest = ep
	select {
	case u.changed <- struct{}{}:
	default:
	}
}

func (u *tunnelExitUpdates) address() netip.AddrPort {
	u.mx.Lock()
	defer u.mx.Unlock()
	return u.latest
}

func (u *tunnelExitUpdates) announce(ctx context.Context, gate *adnl.Gateway, published netip.AddrPort, enableQUIC bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.changed:
		}
		if u.address() == published {
			continue
		}
		// SetAddressList versions have one-second resolution. Coalesce changes
		// in that second so a peer never receives a different list with the same version.
		list := gate.GetAddressList()
		next := time.Unix(int64(list.Version)+1, 0)
		if delay := time.Until(next); delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
		exit := u.address()
		if exit == published {
			continue
		}
		list.Addresses = tunnelAddresses(net.IP(exit.Addr().AsSlice()), exit.Port(), enableQUIC)
		peers := gate.GetActivePeers()
		active := peers[:0]
		for _, peer := range peers {
			stats := peer.Stats()
			if !stats.Closed && stats.Inbound.Packets > 0 {
				// A concurrent RLDP send can build the first root packet during
				// Reinit. Stage B at the existing epoch so that packet cannot
				// advertise A with the new version.
				list.ReinitDate = stats.Reinitialization.LocalEpoch
				peer.SetAddresses(list)
				peer.Reinit()
				active = append(active, peer)
			}
		}
		// A channel NOP carries no address list. After Reinit the next NOP is
		// a signed root packet; install B's addresses and epoch before sending it.
		gate.SetAddressList(list.Addresses)
		published = exit
		for _, peer := range active {
			if ctx.Err() != nil {
				return
			}
			if err := peer.SendNop(ctx); err != nil {
				log.Warn().Err(err).Msg("Failed to announce tunnel exit to peer")
			}
		}
	}
}

func tunnelAddresses(ip net.IP, port uint16, enableQUIC bool) []address.Address {
	result := []address.Address{&address.UDP{IP: ip, Port: int32(port)}}
	if enableQUIC {
		result = append(result, &address.QUIC{IP: ip, Port: int32(port)})
	}
	return result
}
