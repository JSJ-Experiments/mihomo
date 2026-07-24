//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
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
	if len(config.Initial) != 1 || config.Initial[0].Target.String() != "100.88.65.23" ||
		!reflect.DeepEqual(config.Initial[0].Paths, want) {
		t.Fatalf("initial cached connection order = %#v", config.Initial)
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
	if len(config.Initial) != 0 {
		t.Fatalf("initial connection order without a cache = %#v, want automatic selection", config.Initial)
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
	outbound := &Tailscale{
		Base:                 NewBase(BaseOption{Name: "test"}),
		server:               server,
		option:               TailscaleOption{Name: "test"},
		ctx:                  ctx,
		connectionOrderURL:   remote.URL,
		connectionOrderCache: cachePath,
	}
	outbound.refreshTailscaleConnectionOrder()

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
