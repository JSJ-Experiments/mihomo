//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
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
