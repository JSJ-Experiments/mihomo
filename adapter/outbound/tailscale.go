//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/hostinfo"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
	"github.com/metacubex/tailscale/wgengine/magicsock"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

type Tailscale struct {
	*Base
	server      *tsnet.Server
	dnsResolver *dns.Resolver
	option      TailscaleOption
	ctx         context.Context
	cancel      context.CancelFunc
	startOnce   sync.Once
	startErr    error

	backendInitOnce sync.Once
	backendInitCh   chan struct{}
	backendInitErr  error

	serverStarted bool

	connectionOrderURL         string
	connectionOrderCache       string
	connectionOrderRefreshOnce sync.Once

	unregisterDNSResolver func()
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool    `proxy:"accept-routes,omitempty"`
	ExitNode               string   `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool    `proxy:"exit-node-allow-lan-access,omitempty"`
	ConnectionOrder        string   `proxy:"connection-order,omitempty"`
	ConnectionOrderCache   string   `proxy:"connection-order-cache,omitempty"`
	RelayPreferences       []string `proxy:"relay-preferences,omitempty"`
}

func init() {
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		hi.IPNVersion = C.MihomoName + " " + C.Version
	})
	envknob.SetNoLogsNoSupport()
	if runtime.GOOS == "android" { // Android SDK 30 no longer permits Go's net.Interfaces to work (Issue 2293)
		netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
			log.Debugln("[Tailscale] InterfaceGetter: start, IsForceAnet: %v", anet.IsForceAnet())
			ifaces, err := anet.Interfaces()
			if err != nil {
				log.Warnln("[Tailscale] anet.Interfaces failed: %v", err)
				return nil, err
			}
			for _, iff := range ifaces {
				addrs, err := anet.InterfaceAddrsByInterface(&iff)
				if err != nil {
					log.Warnln("[Tailscale] anet.InterfaceAddrsByInterface(%v) failed: %v", iff.Name, err)
					continue
				}
				nif = append(nif, netmon.Interface{
					Interface: &net.Interface{
						Index:        iff.Index,
						MTU:          iff.MTU,
						Name:         iff.Name,
						HardwareAddr: iff.HardwareAddr,
						Flags:        iff.Flags,
					},
					AltAddrs: addrs,
				})
			}

			log.Debugln("[Tailscale] InterfaceGetter: %v", lo.Map(nif, func(item netmon.Interface, index int) string {
				var addrs any
				addrs, err := item.Addrs()
				if err != nil {
					addrs = err
				}
				return fmt.Sprintf("{Name: %s, Addrs: %v, IsUp: %v, IsLoopback: %v}", item.Name, addrs, item.IsUp(), item.IsLoopback())
			}))
			return
		})
	}
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}
	connectionOrder, err := loadTailscaleConnectionOrder(option)
	if err != nil {
		return nil, err
	}

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:        option,
		ctx:           ctx,
		cancel:        cancel,
		backendInitCh: make(chan struct{}),

		connectionOrderURL:   connectionOrder.URL,
		connectionOrderCache: connectionOrder.CachePath,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.server = &tsnet.Server{
		Dir:             option.StateDir,
		Hostname:        option.Hostname,
		AuthKey:         option.AuthKey,
		ControlURL:      option.ControlURL,
		Ephemeral:       option.Ephemeral,
		ConnectionOrder: connectionOrder.Initial,
		SystemDialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Debugln("[Tailscale](%s) SystemDialer: start dial %s %s", option.Name, network, address)
			conn, err := outbound.dialer.DialContext(ctx, network, address)
			log.Debugln("[Tailscale](%s) SystemDialer: finish dial %s %s, err: %v", option.Name, network, address, err)
			return conn, err
		},
		SystemPacketListener: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			log.Debugln("[Tailscale](%s) SystemPacketListener: start listen %s %s", option.Name, network, address)
			pc, err := outbound.dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
			log.Debugln("[Tailscale](%s) SystemPacketListener: finish listen %s %s, err: %v", option.Name, network, address, err)
			return pc, err
		},
		ExtraRootCAs: ca.GetCertPool(),
		LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
			log.Debugln("[Tailscale](%s) LookupHook: start lookup %s", option.Name, host)
			ips, err := resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
			log.Debugln("[Tailscale](%s) LookupHook: finish lookup %s, ips: %v, err: %v", option.Name, host, ips, err)
			return ips, err
		},
		UserLogf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			log.Debugln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
	}
	dnsTransport := tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(dnsTransport)
	outbound.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(option.Name, dnsTransport)
	return outbound, nil
}

type tailscaleConnectionOrderConfig struct {
	Initial   []magicsock.ConnectionOrder
	URL       string
	CachePath string
}

func loadTailscaleConnectionOrder(option TailscaleOption) (tailscaleConnectionOrderConfig, error) {
	var config tailscaleConnectionOrderConfig
	orders := make(map[netip.Addr][]string)
	if option.ConnectionOrder != "" {
		if isTailscaleConnectionOrderURL(option.ConnectionOrder) {
			config.URL = option.ConnectionOrder
			config.CachePath = option.ConnectionOrderCache
			if config.CachePath == "" {
				config.CachePath = filepath.Join(option.StateDir, "connection-order.yaml")
			} else {
				config.CachePath = C.Path.Resolve(config.CachePath)
			}
			if !C.Path.IsSafePath(config.CachePath) {
				return config, C.Path.ErrNotSafePath(config.CachePath)
			}

			data, err := os.ReadFile(config.CachePath)
			if err == nil {
				orders, err = parseTailscaleConnectionOrder(data, true)
				if err != nil {
					log.Warnln("[Tailscale](%s) ignoring invalid cached connection order %s: %v", option.Name, config.CachePath, err)
					orders = make(map[netip.Addr][]string)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				log.Warnln("[Tailscale](%s) cannot read cached connection order %s: %v", option.Name, config.CachePath, err)
			}
		} else {
			data, err := readTailscaleConnectionOrder(option.ConnectionOrder, option.DialerProxy)
			if err != nil {
				return config, fmt.Errorf("read tailscale connection-order file: %w", err)
			}
			orders, err = parseTailscaleConnectionOrder(data, true)
			if err != nil {
				return config, fmt.Errorf("parse tailscale connection-order file: %w", err)
			}
		}
	}

	if err := mergeTailscaleRelayPreferences(orders, option); err != nil {
		return config, err
	}
	config.Initial = tailscaleConnectionOrdersFromMap(orders)
	return config, nil
}

func mergeTailscaleRelayPreferences(orders map[netip.Addr][]string, option TailscaleOption) error {
	// relay-preferences is retained for compatibility. A per-device entry in
	// the new file wins when both configurations target the same exit node.
	if len(option.RelayPreferences) != 0 {
		exitNodeIP, err := netip.ParseAddr(option.ExitNode)
		if err != nil {
			return fmt.Errorf("tailscale relay-preferences requires exit-node to be a Tailscale IP address: %w", err)
		}
		if _, exists := orders[exitNodeIP]; !exists {
			paths := normalizeTailscaleConnectionOrder(option.RelayPreferences, false)
			if len(paths) != 0 {
				orders[exitNodeIP] = paths
			}
		}
	}
	return nil
}

func tailscaleConnectionOrdersFromMap(orders map[netip.Addr][]string) []magicsock.ConnectionOrder {
	targets := make([]netip.Addr, 0, len(orders))
	for target := range orders {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Compare(targets[j]) < 0
	})
	result := make([]magicsock.ConnectionOrder, 0, len(targets))
	for _, target := range targets {
		result = append(result, magicsock.ConnectionOrder{
			Target: target,
			Paths:  orders[target],
		})
	}
	return result
}

const maxTailscaleConnectionOrderSize = 1 << 20

func isTailscaleConnectionOrderURL(location string) bool {
	return strings.HasPrefix(strings.ToLower(location), "http://") ||
		strings.HasPrefix(strings.ToLower(location), "https://")
}

func readTailscaleConnectionOrder(location string, proxy string) ([]byte, error) {
	if isTailscaleConnectionOrderURL(location) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		response, err := mihomoHttp.HttpRequest(ctx, location, http.MethodGet, nil, nil, mihomoHttp.WithSpecialProxy(proxy))
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			return nil, fmt.Errorf("unexpected HTTP status: %s", response.Status)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, maxTailscaleConnectionOrderSize+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxTailscaleConnectionOrderSize {
			return nil, fmt.Errorf("connection-order file exceeds %d bytes", maxTailscaleConnectionOrderSize)
		}
		return data, nil
	}

	path := C.Path.Resolve(location)
	if !C.Path.IsSafePath(path) {
		return nil, C.Path.ErrNotSafePath(path)
	}
	return os.ReadFile(path)
}

func writeTailscaleConnectionOrderCache(path string, data []byte) error {
	if len(data) > maxTailscaleConnectionOrderSize {
		return fmt.Errorf("connection-order file exceeds %d bytes", maxTailscaleConnectionOrderSize)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tempFile, err := os.CreateTemp(dir, ".connection-order-*.tmp")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if err = tempFile.Chmod(0o644); err == nil {
		_, err = tempFile.Write(data)
	}
	if closeErr := tempFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func parseTailscaleConnectionOrder(data []byte, addDirectIfMissing bool) (map[netip.Addr][]string, error) {
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	orders := make(map[netip.Addr][]string, len(raw))
	for targetString, rawPaths := range raw {
		target, err := netip.ParseAddr(strings.TrimSpace(targetString))
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", targetString, err)
		}
		paths := normalizeTailscaleConnectionOrder(rawPaths, addDirectIfMissing)
		if len(paths) != 0 {
			orders[target] = paths
		}
	}
	return orders, nil
}

func normalizeTailscaleConnectionOrder(rawPaths []string, addDirectIfMissing bool) []string {
	paths := make([]string, 0, len(rawPaths)+1)
	seen := make(map[string]struct{}, len(rawPaths)+1)
	hasDirect := false
	for _, rawPath := range rawPaths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}
		if strings.EqualFold(path, "AUTO") {
			if len(rawPaths) == 1 {
				return nil
			}
			continue
		}
		if strings.EqualFold(path, "DIRECT") {
			path = "DIRECT"
			hasDirect = true
		} else if ip, err := netip.ParseAddr(path); err == nil {
			path = ip.String()
		} else {
			path = strings.ToUpper(path)
		}
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		paths = append(paths, path)
	}
	if addDirectIfMissing && len(paths) != 0 && !hasDirect {
		paths = append([]string{"DIRECT"}, paths...)
	}
	return paths
}

func (t *Tailscale) start() error {
	t.startOnce.Do(func() {
		if err := t.server.Start(); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		t.serverStarted = true
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if err := t.applyPrefs(ctx); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		go t.watchBackendState()
	})
	return t.startErr
}

func (t *Tailscale) ensureStarted(ctx context.Context) error {
	if err := t.start(); err != nil {
		return err
	}
	if err := t.waitBackendInitialized(ctx); err != nil {
		return err
	}
	t.connectionOrderRefreshOnce.Do(func() {
		if t.connectionOrderURL != "" {
			go t.refreshTailscaleConnectionOrder()
		}
	})
	return nil
}

func (t *Tailscale) refreshTailscaleConnectionOrder() {
	data, err := readTailscaleConnectionOrder(t.connectionOrderURL, t.option.DialerProxy)
	if err != nil {
		log.Warnln("[Tailscale](%s) refresh connection order failed; retaining cached order: %v", t.Name(), err)
		return
	}
	orders, err := parseTailscaleConnectionOrder(data, true)
	if err != nil {
		log.Warnln("[Tailscale](%s) ignoring invalid remote connection order; retaining cached order: %v", t.Name(), err)
		return
	}
	if err = mergeTailscaleRelayPreferences(orders, t.option); err != nil {
		log.Warnln("[Tailscale](%s) merge connection order failed; retaining cached order: %v", t.Name(), err)
		return
	}

	if t.connectionOrderCache != "" {
		if err = writeTailscaleConnectionOrderCache(t.connectionOrderCache, data); err != nil {
			log.Warnln("[Tailscale](%s) save connection order cache %s failed: %v", t.Name(), t.connectionOrderCache, err)
		} else {
			log.Infoln("[Tailscale](%s) updated connection order cache %s", t.Name(), t.connectionOrderCache)
		}
	}

	select {
	case <-t.ctx.Done():
		return
	default:
	}
	t.server.SetConnectionOrder(tailscaleConnectionOrdersFromMap(orders))
	log.Infoln("[Tailscale](%s) applied remote connection order", t.Name())
}

func (t *Tailscale) watchBackendState() {
	lc, err := t.server.LocalClient()
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialState)
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	defer watcher.Close()

	backendInitialized := false
	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(t.option)
	for {
		n, err := watcher.Next()
		if err != nil {
			t.setBackendInitialized(err)
			return
		}
		if n.State == nil {
			continue
		}

		if *n.State != ipn.NoState && !backendInitialized {
			t.setBackendInitialized(nil)
			backendInitialized = true
			if !exitNodeNeedsStatus {
				return
			}
		}
		if exitNodeNeedsStatus && *n.State == ipn.Running {
			if err := t.applyExitNodePrefs(t.ctx); err != nil {
				log.Warnln("[Tailscale](%s) set exit node failed: %v", t.Name(), err)
			}
			return
		}
	}
}

func (t *Tailscale) setBackendInitialized(err error) {
	t.backendInitOnce.Do(func() {
		t.backendInitErr = err
		close(t.backendInitCh)
	})
}

func (t *Tailscale) waitBackendInitialized(ctx context.Context) error {
	select {
	case <-t.backendInitCh:
		return t.backendInitErr
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Tailscale) applyPrefs(ctx context.Context) error {
	mp, err := buildTailscaleMaskedPrefs(t.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (t *Tailscale) applyExitNodePrefs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if t.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *t.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(t.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	netStack, err := t.server.Netstack(ctx)
	if err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	options := t.DialOptions()
	options = append(options, dialer.WithResolver(t.dnsResolver))
	options = append(options, dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
		if err != nil {
			return nil, err
		}
		src := v4
		if dst.Addr().Is6() {
			src = v6
		}
		tcpConn, err := netStack.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	})))
	var conn net.Conn
	conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	src := v4
	if metadata.DstIP.Is6() {
		src = v6
	}
	pc, err := t.server.ListenPacket("udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, t.prefer, t.dnsResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.tailscale.ensureStarted(ctx); err != nil {
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	lc, err := t.tailscale.server.LocalClient()
	if err != nil {
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (t *Tailscale) Close() error {
	t.cancel()
	if t.unregisterDNSResolver != nil {
		t.unregisterDNSResolver()
	}
	t.startOnce.Do(func() {
		t.startErr = errors.New("tailscale outbound closed")
	})
	if t.server != nil && t.serverStarted { // tsnet.Server.Close() must not be called before or concurrently with Start.
		return t.server.Close()
	}
	return nil
}
