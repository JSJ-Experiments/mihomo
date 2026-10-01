//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/tsnet"
)

func TestParseTailscaleConnectionOrder(t *testing.T) {
	data := []byte(`
100.88.65.23:
  - DIRECT
100.113.237.90:
  - TYO
  - 100.91.245.79
  - DIRECT
100.100.100.100:
  - SIN
100.101.102.103: []
`)
	orders, err := parseTailscaleConnectionOrder(data, true)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]string{
		"100.88.65.23":    {"DIRECT"},
		"100.113.237.90":  {"TYO", "100.91.245.79", "DIRECT"},
		"100.100.100.100": {"DIRECT", "SIN"},
	}
	for targetString, want := range tests {
		target := netip.MustParseAddr(targetString)
		if got := orders[target]; !reflect.DeepEqual(got, want) {
			t.Errorf("order for %s = %v, want %v", target, got, want)
		}
	}
	if target := netip.MustParseAddr("100.101.102.103"); orders[target] != nil {
		t.Errorf("empty order for %s should retain automatic path selection", target)
	}
}

func TestNormalizeLegacyRelayPreferences(t *testing.T) {
	got := normalizeTailscaleConnectionOrder([]string{"tyo", "100.91.245.79"}, false)
	want := []string{"TYO", "100.91.245.79"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy relay preferences = %v, want %v", got, want)
	}
}

func TestParseTailscaleConnectionOrderRejectsInvalidTarget(t *testing.T) {
	if _, err := parseTailscaleConnectionOrder([]byte("not-an-ip: [DIRECT]"), true); err == nil {
		t.Fatal("invalid target was accepted")
	}
}

func TestReadTailscaleConnectionOrderURL(t *testing.T) {
	want := []byte("100.88.65.23: [DIRECT]\n")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/connection-order.yaml" {
			http.NotFound(response, request)
			return
		}
		_, _ = response.Write(want)
	}))
	defer server.Close()

	got, err := readTailscaleConnectionOrder(server.URL+"/connection-order.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("downloaded connection order = %q, want %q", got, want)
	}
}

func TestLoadTailscaleConnectionOrderURLUsesCache(t *testing.T) {
	oldHomeDir := C.Path.HomeDir()
	homeDir := t.TempDir()
	C.SetHomeDir(homeDir)
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
	})

	stateDir := filepath.Join(homeDir, "tailscale-test")
	cachePath := filepath.Join(stateDir, "connection-order.yaml")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("100.88.65.23: [DIRECT]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	config, err := loadTailscaleConnectionOrder(TailscaleOption{
		Name:            "test",
		StateDir:        stateDir,
		ConnectionOrder: "https://example.invalid/connection-order.yaml",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.URL != "https://example.invalid/connection-order.yaml" {
		t.Fatalf("connection order URL = %q", config.URL)
	}
	if config.CachePath != cachePath {
		t.Fatalf("cache path = %q, want %q", config.CachePath, cachePath)
	}
	want := []string{"DIRECT"}
	if !reflect.DeepEqual(config.Base[netip.MustParseAddr("100.88.65.23")], want) {
		t.Fatalf("initial cached connection order = %#v", config.Base)
	}
	if config.LocalPath != filepath.Join(stateDir, "connection-order-local.yaml") {
		t.Fatalf("local override path = %q", config.LocalPath)
	}
}

func TestLoadTailscaleConnectionOrderURLWithoutCacheUsesAuto(t *testing.T) {
	oldHomeDir := C.Path.HomeDir()
	homeDir := t.TempDir()
	C.SetHomeDir(homeDir)
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
	})

	config, err := loadTailscaleConnectionOrder(TailscaleOption{
		Name:            "test",
		StateDir:        filepath.Join(homeDir, "tailscale-test"),
		ConnectionOrder: "https://example.invalid/connection-order.yaml",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Base) != 0 {
		t.Fatalf("initial connection order without a cache = %#v, want automatic selection", config.Base)
	}
}

func TestLoadTailscaleConnectionOrderLocalOverrides(t *testing.T) {
	oldHomeDir := C.Path.HomeDir()
	homeDir := t.TempDir()
	C.SetHomeDir(homeDir)
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
	})

	stateDir := filepath.Join(homeDir, "tailscale-test")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "connection-order.yaml"), []byte(`
100.88.65.23: [TYO]
100.113.237.90: [SIN]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "connection-order-local.yaml"), []byte(`
100.88.65.23: [AUTO]
100.113.237.90: [TYO]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	config, err := loadTailscaleConnectionOrder(TailscaleOption{
		Name:            "test",
		StateDir:        stateDir,
		ConnectionOrder: "https://example.invalid/connection-order.yaml",
	})
	if err != nil {
		t.Fatal(err)
	}
	effective := mergeTailscaleConnectionOrderMaps(config.Base, config.Overrides)
	if _, exists := effective[netip.MustParseAddr("100.88.65.23")]; exists {
		t.Fatal("explicit local AUTO did not override the remote order")
	}
	want := []string{"DIRECT", "TYO"}
	if got := effective[netip.MustParseAddr("100.113.237.90")]; !reflect.DeepEqual(got, want) {
		t.Fatalf("local effective order = %v, want %v", got, want)
	}
}

func TestMarshalTailscaleConnectionOrderOverridesPreservesAuto(t *testing.T) {
	target := netip.MustParseAddr("100.88.65.23")
	data, err := marshalTailscaleConnectionOrderOverrides(map[netip.Addr][]string{target: nil})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseTailscaleConnectionOrderOverrides(data)
	if err != nil {
		t.Fatal(err)
	}
	paths, exists := got[target]
	if !exists || len(paths) != 0 {
		t.Fatalf("AUTO override round trip = %v, exists=%v", paths, exists)
	}
}

func TestSetTailscaleConnectionOrderOverridePersists(t *testing.T) {
	target := netip.MustParseAddr("100.88.65.23")
	localPath := filepath.Join(t.TempDir(), "connection-order-local.yaml")
	server := new(tsnet.Server)
	outbound := &Tailscale{
		server:                   server,
		connectionOrderLocal:     localPath,
		connectionOrderBase:      map[netip.Addr][]string{target: {"DIRECT", "SIN"}},
		connectionOrderOverrides: make(map[netip.Addr][]string),
	}
	if err := outbound.SetConnectionOrderOverride(target, []string{"TYO"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"DIRECT", "TYO"}
	if len(server.ConnectionOrder) != 1 || !reflect.DeepEqual(server.ConnectionOrder[0].Paths, want) {
		t.Fatalf("live local order = %#v, want %v", server.ConnectionOrder, want)
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	overrides, err := parseTailscaleConnectionOrderOverrides(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := overrides[target]; !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted local order = %v, want %v", got, want)
	}

	if err = outbound.SetConnectionOrderOverride(target, nil); err != nil {
		t.Fatal(err)
	}
	if len(server.ConnectionOrder) != 0 {
		t.Fatalf("explicit AUTO live order = %#v, want none", server.ConnectionOrder)
	}
}

func TestValidateTailscaleServiceForwards(t *testing.T) {
	valid := []TailscaleServiceForward{{Name: "ssh", Listen: 8022, Target: "127.0.0.1:8022"}}
	if err := validateTailscaleServiceForwards(valid); err != nil {
		t.Fatalf("valid service forward rejected: %v", err)
	}
	if err := validateTailscaleServiceForwards([]TailscaleServiceForward{
		{Name: "unsafe", Listen: 8022, Target: "192.0.2.1:22"},
	}); err == nil {
		t.Fatal("non-loopback service target accepted")
	}
	if err := validateTailscaleServiceForwards([]TailscaleServiceForward{
		{Name: "one", Listen: 8022, Target: "127.0.0.1:22"},
		{Name: "two", Listen: 8022, Target: "127.0.0.1:23"},
	}); err == nil {
		t.Fatal("duplicate service listen port accepted")
	}
}

func TestLazyTailscaleServiceForwardsDoNotStartOnConstruction(t *testing.T) {
	oldHomeDir := C.Path.HomeDir()
	homeDir := t.TempDir()
	C.SetHomeDir(homeDir)
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
	})

	outbound, err := NewTailscale(TailscaleOption{
		Name:                "lazy-management-test",
		Hostname:            "lazy-management-test",
		StateDir:            filepath.Join(homeDir, "tailscale-lazy-management-test"),
		ServiceForwards:     []TailscaleServiceForward{{Name: "ssh", Listen: 8022, Target: "127.0.0.1:8022"}},
		ServiceForwardsLazy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbound.Close() })

	if outbound.serverStarted {
		t.Fatal("lazy service forward started tsnet during outbound construction")
	}
	if len(outbound.serviceListeners) != 0 {
		t.Fatalf("lazy service forward installed %d listener(s) before first use", len(outbound.serviceListeners))
	}
}

func TestRefreshTailscaleConnectionOrderUpdatesCacheAndServer(t *testing.T) {
	data := []byte("100.113.237.90: [TYO, 100.91.245.79]\n")
	remote := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(data)
	}))
	defer remote.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cachePath := filepath.Join(t.TempDir(), "connection-order.yaml")
	server := new(tsnet.Server)
	recordingDialer := new(tailscaleConnectionOrderTestDialer)
	outbound := &Tailscale{
		Base:                     NewBase(BaseOption{Name: "test"}),
		server:                   server,
		option:                   TailscaleOption{Name: "test"},
		ctx:                      ctx,
		connectionOrderURL:       remote.URL,
		connectionOrderCache:     cachePath,
		connectionOrderBase:      make(map[netip.Addr][]string),
		connectionOrderOverrides: make(map[netip.Addr][]string),
	}
	outbound.dialer = recordingDialer
	if !outbound.refreshTailscaleConnectionOrder() {
		t.Fatal("remote connection order refresh failed")
	}
	if recordingDialer.calls == 0 {
		t.Fatal("connection order refresh did not use the Tailscale bootstrap dialer")
	}

	cached, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cached, data) {
		t.Fatalf("cached connection order = %q, want %q", cached, data)
	}
	want := []string{"DIRECT", "TYO", "100.91.245.79"}
	if len(server.ConnectionOrder) != 1 ||
		server.ConnectionOrder[0].Target.String() != "100.113.237.90" ||
		!reflect.DeepEqual(server.ConnectionOrder[0].Paths, want) {
		t.Fatalf("live connection order = %#v", server.ConnectionOrder)
	}
}

type tailscaleConnectionOrderTestDialer struct {
	calls int
}

func (d *tailscaleConnectionOrderTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls++
	return new(net.Dialer).DialContext(ctx, network, address)
}

func (d *tailscaleConnectionOrderTestDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	return new(net.ListenConfig).ListenPacket(ctx, network, address)
}
