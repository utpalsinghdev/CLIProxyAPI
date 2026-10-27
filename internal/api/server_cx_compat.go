package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	cxWarmHeader = "X-CX-Warm-Account"
	cxWarmBody   = `{"model":"gpt-6-luna","input":"Reply with OK only.","stream":false,"reasoning":{"effort":"low"}}`
	cxWarmLimit  = 16 << 20
)

// cxCompatibilityMiddleware rejects use of the targeted-warm header except for its
// single supported, loopback-only request shape.
func (s *Server) cxCompatibilityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.Header.Values(cxWarmHeader)
		compatPath := c.Request.URL != nil && cxCompatibilityPath(c.Request.URL.Path)
		if (s.cfg.CXCompatibility.Enabled && compatPath) || len(values) > 0 {
			if c.Request.Header.Get("Origin") != "" || strings.EqualFold(strings.TrimSpace(c.Request.Header.Get("Sec-Fetch-Site")), "cross-site") {
				cxError(c, http.StatusForbidden, "cross_site_request", "cross-site requests are not allowed")
				return
			}
		}
		if s.cfg.CXCompatibility.Enabled && compatPath && !cxProtocolGuard(c) {
			return
		}
		if s.cfg.CXCompatibility.Enabled && !compatPath && c.FullPath() == "" && len(values) == 0 {
			cxError(c, http.StatusNotFound, "not_found", "Not found")
			return
		}
		if len(values) == 0 {
			canonical := false
			if s.cfg.CXCompatibility.Enabled && c.Request.Method == http.MethodPost && (c.Request.URL.Path == "/v1/responses" || c.Request.URL.Path == "/v1/responses/compact") {
				var ok bool
				canonical, ok = s.cxCanonicalAccounts(c, "")
				if !ok {
					return
				}
			}
			if !s.cfg.CXCompatibility.Enabled || s.cxPrepareResponses(c, canonical) {
				c.Next()
			}
			return
		}
		if !s.cfg.CXCompatibility.Enabled {
			cxError(c, http.StatusForbidden, "cx_compatibility_disabled", "CX targeted warming is disabled")
			return
		}
		if len(values) != 1 || values[0] == "" {
			cxError(c, http.StatusBadRequest, "invalid_target", "exactly one non-empty target account is required")
			return
		}
		account := values[0]
		if len(account) > 320 || strings.TrimSpace(account) == "" || strings.TrimSpace(account) != account {
			cxError(c, http.StatusBadRequest, "invalid_target", "target account is invalid")
			return
		}
		if !cxWarmJSONObject(c) {
			return
		}
		if !isLoopbackRemote(c.Request.RemoteAddr) {
			cxError(c, http.StatusForbidden, "loopback_required", "targeted warming requires a loopback connection")
			return
		}
		if !cxWarmRequest(c.Request) {
			cxError(c, http.StatusBadRequest, "unsupported_warm_request", "targeted warming is not allowed for this request")
			return
		}
		if !validCXWarmBody(c) {
			cxError(c, http.StatusBadRequest, "invalid_warm_request", "request body does not match the supported warm request")
			return
		}
		canonical, ok := s.cxCanonicalAccounts(c, account)
		if !ok {
			return
		}
		if !canonical {
			id, found := s.resolveCXWarmAccount(account)
			if !found {
				cxError(c, http.StatusNotFound, "target_not_found", "target account was not found")
				return
			}
			c.Request = c.Request.WithContext(handlers.WithPinnedAuthID(c.Request.Context(), id))
		}
		c.Request.Header.Del(cxWarmHeader)
		if s.cxPrepareResponses(c, true) {
			c.Next()
		}
	}
}

func cxWarmRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL != nil && r.URL.Path == "/v1/responses"
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validCXWarmBody(c *gin.Context) bool {
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, cxWarmLimit))
	if err != nil {
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return false
	}
	fields := make(map[string]json.RawMessage, 4)
	for dec.More() {
		keyToken, errKey := dec.Token()
		key, ok := keyToken.(string)
		if errKey != nil || !ok {
			return false
		}
		if _, exists := fields[key]; exists {
			return false
		}
		var value json.RawMessage
		if errValue := dec.Decode(&value); errValue != nil {
			return false
		}
		fields[key] = value
	}
	if _, errEnd := dec.Token(); errEnd != nil || len(fields) != 4 {
		return false
	}
	if tok, errTrailing := dec.Token(); errTrailing != io.EOF || tok != nil {
		return false
	}
	var model, input string
	var stream bool
	var reasoning struct {
		Effort string `json:"effort"`
	}
	if json.Unmarshal(fields["model"], &model) != nil || model != "gpt-6-luna" ||
		json.Unmarshal(fields["input"], &input) != nil || input != "Reply with OK only." ||
		string(fields["stream"]) == "null" || json.Unmarshal(fields["stream"], &stream) != nil || stream ||
		json.Unmarshal(fields["reasoning"], &reasoning) != nil || reasoning.Effort != "low" {
		return false
	}
	var reasoningFields map[string]json.RawMessage
	if json.Unmarshal(fields["reasoning"], &reasoningFields) != nil || len(reasoningFields) != 1 {
		return false
	}
	return true
}

func (s *Server) resolveCXWarmAccount(email string) (string, bool) {
	if s.handlers == nil || s.handlers.AuthManager == nil {
		return "", false
	}
	var id string
	for _, record := range s.handlers.AuthManager.List() {
		if record == nil || record.Disabled || record.Status == coreauth.StatusDisabled || !strings.EqualFold(strings.TrimSpace(record.Provider), "codex") {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(record.Attributes["auth_kind"]))
		if kind == "" {
			kind, _ = record.Metadata["auth_kind"].(string)
			kind = strings.ToLower(strings.TrimSpace(kind))
		}
		if kind != "oauth" {
			continue
		}
		candidate, _ := record.Metadata["email"].(string)
		if candidate != email {
			continue
		}
		if id != "" {
			return "", false
		}
		id = record.ID
	}
	return id, id != ""
}

func cxError(c *gin.Context, status int, code, message string) {
	errorType := "invalid_request_error"
	if status >= http.StatusInternalServerError {
		errorType = "server_error"
	} else if status == http.StatusUnauthorized {
		errorType = "authentication_error"
	} else if status == http.StatusTooManyRequests {
		errorType = "rate_limit_error"
	}
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"message": message, "type": errorType, "code": code}})
}

func (s *Server) cxHealth(c *gin.Context) {
	if !s.cfg.CXCompatibility.Enabled {
		cxError(c, http.StatusNotFound, "not_found", "Not found")
		return
	}
	count := 0
	if home := strings.TrimSpace(s.cfg.CXCompatibility.SourceHome); home != "" {
		if !filepath.IsAbs(home) || s.cfg.Home.Enabled {
			cxError(c, http.StatusServiceUnavailable, "cx_store_unavailable", "CX account source is unavailable")
			return
		}
		accounts, err := cxcompat.NewStore(home).ListOAuthAccounts()
		if err != nil {
			cxError(c, http.StatusServiceUnavailable, "cx_store_unavailable", "CX account source is unavailable")
			return
		}
		count = len(accounts)
	} else if s.handlers != nil && s.handlers.AuthManager != nil {
		for _, record := range s.handlers.AuthManager.List() {
			if record != nil && !record.Disabled && record.Status != coreauth.StatusDisabled && strings.EqualFold(strings.TrimSpace(record.Provider), "codex") {
				kind := strings.ToLower(strings.TrimSpace(record.Attributes["auth_kind"]))
				if kind == "" {
					kind, _ = record.Metadata["auth_kind"].(string)
				}
				if strings.EqualFold(strings.TrimSpace(kind), "oauth") {
					count++
				}
			}
		}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "accounts": count, "targetedWarming": true})
}
