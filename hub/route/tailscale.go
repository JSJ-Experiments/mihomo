//go:build with_gvisor && !no_tailscale

package route

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/samber/lo"
)

type tailscaleOutboundInfo struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
}

type proxyAdapterUnwrapper interface {
	UnderlyingProxyAdapter() C.ProxyAdapter
}

func asTailscale(adapter C.ProxyAdapter) (*outbound.Tailscale, bool) {
	for adapter != nil {
		if tailscale, ok := adapter.(*outbound.Tailscale); ok {
			return tailscale, true
		}
		unwrapper, ok := adapter.(proxyAdapterUnwrapper)
		if !ok {
			break
		}
		next := unwrapper.UnderlyingProxyAdapter()
		if next == adapter {
			break
		}
		adapter = next
	}
	return nil, false
}

func tailscaleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getTailscaleOutbounds)
	r.Route("/{providerName}/{name}", func(r chi.Router) {
		r.Use(findTailscaleOutbound)
		r.Get("/", getTailscaleStatus)
		r.Get("/devices", getTailscaleDevices)
		r.Get("/paths", getTailscalePathOptions)
		r.Get("/orders", getTailscaleConnectionOrders)
		r.Route("/devices/{ip}", func(r chi.Router) {
			r.Put("/order", putTailscaleConnectionOrder)
			r.Delete("/order", deleteTailscaleConnectionOrder)
			r.Post("/probe", postTailscalePathProbe)
		})
	})
	return r
}

func tailscaleOutbounds() []tailscaleOutboundInfo {
	var result []tailscaleOutboundInfo
	for providerName, provider := range tunnel.Providers() {
		for _, proxy := range provider.Proxies() {
			if _, ok := asTailscale(proxy.Adapter()); ok {
				result = append(result, tailscaleOutboundInfo{Provider: providerName, Name: proxy.Name()})
			}
		}
	}
	for name, proxy := range tunnel.Proxies() {
		if _, ok := asTailscale(proxy.Adapter()); ok {
			result = append(result, tailscaleOutboundInfo{Provider: "@global", Name: name})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Provider != result[j].Provider {
			return result[i].Provider < result[j].Provider
		}
		return result[i].Name < result[j].Name
	})
	return lo.UniqBy(result, func(info tailscaleOutboundInfo) string {
		return info.Provider + "\x00" + info.Name
	})
}

type tailscaleOutboundContextKey struct{}

func findTailscaleOutbound(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerName := getEscapeParam(r, "providerName")
		name := getEscapeParam(r, "name")
		var proxy C.Proxy
		if providerName == "@global" {
			proxy = tunnel.Proxies()[name]
		} else {
			var provider P.ProxyProvider
			if candidate, ok := tunnel.Providers()[providerName]; ok {
				provider = candidate
			}
			if provider != nil {
				proxy, _ = lo.Find(provider.Proxies(), func(candidate C.Proxy) bool {
					return candidate.Name() == name
				})
			}
		}
		if proxy == nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		tailscale, ok := asTailscale(proxy.Adapter())
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("proxy is not a Tailscale outbound"))
			return
		}
		ctx := context.WithValue(r.Context(), tailscaleOutboundContextKey{}, tailscale)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tailscaleFromRequest(r *http.Request) *outbound.Tailscale {
	return r.Context().Value(tailscaleOutboundContextKey{}).(*outbound.Tailscale)
}

func getTailscaleOutbounds(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"outbounds": tailscaleOutbounds()})
}

func getTailscaleStatus(w http.ResponseWriter, r *http.Request) {
	tailscale := tailscaleFromRequest(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	devices, err := tailscale.TailscaleDevices(ctx)
	if err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	options, err := tailscale.ConnectionPathOptions(ctx)
	if err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	render.JSON(w, r, render.M{
		"devices": devices,
		"orders":  tailscale.ConnectionOrderStates(),
		"paths":   options,
	})
}

func getTailscaleDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	devices, err := tailscaleFromRequest(r).TailscaleDevices(ctx)
	if err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	render.JSON(w, r, render.M{"devices": devices})
}

func getTailscalePathOptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	options, err := tailscaleFromRequest(r).ConnectionPathOptions(ctx)
	if err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	render.JSON(w, r, options)
}

func getTailscaleConnectionOrders(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"orders": tailscaleFromRequest(r).ConnectionOrderStates()})
}

func parseTailscaleTarget(r *http.Request) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSpace(getEscapeParam(r, "ip")))
}

func putTailscaleConnectionOrder(w http.ResponseWriter, r *http.Request) {
	target, err := parseTailscaleTarget(r)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid Tailscale device IP"))
		return
	}
	request := struct {
		Paths []string `json:"paths"`
	}{}
	if err = render.DecodeJSON(r.Body, &request); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err = tailscaleFromRequest(r).SetConnectionOrderOverride(target, request.Paths); err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func deleteTailscaleConnectionOrder(w http.ResponseWriter, r *http.Request) {
	target, err := parseTailscaleTarget(r)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid Tailscale device IP"))
		return
	}
	if err = tailscaleFromRequest(r).ClearConnectionOrderOverride(target); err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func postTailscalePathProbe(w http.ResponseWriter, r *http.Request) {
	target, err := parseTailscaleTarget(r)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid Tailscale device IP"))
		return
	}
	request := struct {
		Paths         []string `json:"paths"`
		TimeoutMillis int      `json:"timeoutMillis"`
	}{}
	if err = render.DecodeJSON(r.Body, &request); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if len(request.Paths) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("at least one path is required"))
		return
	}
	if request.TimeoutMillis == 0 {
		request.TimeoutMillis = 3000
	}
	if request.TimeoutMillis < 500 || request.TimeoutMillis > 10000 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("timeoutMillis must be between 500 and 10000"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(request.TimeoutMillis)*time.Millisecond)
	defer cancel()
	results, err := tailscaleFromRequest(r).ProbeConnectionPaths(ctx, target, request.Paths)
	if err != nil {
		renderTailscaleError(w, r, err)
		return
	}
	render.JSON(w, r, render.M{"results": results})
}

func renderTailscaleError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusServiceUnavailable
	if r.Context().Err() != nil {
		status = http.StatusRequestTimeout
	}
	render.Status(r, status)
	render.JSON(w, r, newError(err.Error()))
}
