//go:build !with_gvisor || no_tailscale

package route

import (
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func tailscaleRouter() http.Handler {
	r := chi.NewRouter()
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}))
	return r
}
