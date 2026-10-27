package api

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
)

func (s *Server) validateCXIngress() error {
	cfg := s.cfg.CXCompatibility
	if cfg.Enabled && !cfg.ProtectedListeners {
		return fmt.Errorf("CX compatibility requires protected-listeners")
	}
	if (cfg.Keyless || cfg.ProtectedListeners) && !cfg.Enabled {
		return fmt.Errorf("CX protected listeners and keyless access require cx-compatibility.enabled")
	}
	if cfg.Keyless && (!cfg.ProtectedListeners || !filepath.IsAbs(cfg.SourceHome)) {
		return fmt.Errorf("CX keyless access requires protected-listeners and an absolute source-home")
	}
	return nil
}

// cxAPIAuthMiddleware exempts only CX's original API routes. Management, native
// Chat Completions, and WebSocket upgrades keep their existing authentication.
func (s *Server) cxAPIAuthMiddleware() gin.HandlerFunc {
	standardAuth := AuthMiddleware(s.accessManager)
	return func(c *gin.Context) {
		cfg := s.cfg.CXCompatibility
		if cfg.Enabled && cfg.Keyless && cfg.ProtectedListeners && filepath.IsAbs(cfg.SourceHome) && cxKeylessRequest(c.Request) {
			if !cxcompat.IsProtectedPeer(c.Request.RemoteAddr) {
				cxError(c, http.StatusForbidden, "protected_peer_required", "CX keyless access requires a loopback or Tailscale connection")
				return
			}
			c.Next()
			return
		}
		standardAuth(c)
	}
}

func cxKeylessRequest(req *http.Request) bool {
	if req.URL == nil {
		return false
	}
	switch req.URL.Path {
	case "/v1/models":
		return req.Method == http.MethodGet
	case "/v1/responses", "/v1/responses/compact":
		return req.Method == http.MethodPost
	default:
		return false
	}
}
