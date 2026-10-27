package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

// CX rejects malformed JSON before checking the optional warm-routing exception.
func cxWarmJSONObject(c *gin.Context) bool {
	body, err := cxcompat.ReadRequest(c.Writer, c.Request)
	if err != nil {
		cxRequestError(c, err)
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body.Raw))
	return true
}

func cxCompatibilityPath(path string) bool {
	switch path {
	case "/health", "/v1/models", "/v1/responses", "/v1/responses/compact":
		return true
	default:
		return false
	}
}

// cxProtocolGuard keeps CX's HTTP validation before authentication or execution.
// Native WebSocket upgrades remain available; plain GET Responses requests do not start inference.
func cxProtocolGuard(c *gin.Context) bool {
	path := c.Request.URL.Path
	method := http.MethodPost
	if path == "/health" || path == "/v1/models" {
		method = http.MethodGet
	}
	if path == "/v1/responses" && c.Request.Method == http.MethodGet && strings.EqualFold(c.Request.Header.Get("Upgrade"), "websocket") {
		return true
	}
	if c.Request.Method != method {
		c.Header("Allow", method)
		cxError(c, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return false
	}
	if path == "/v1/models" {
		version := c.Request.URL.Query().Get("client_version")
		if _, exists := c.Request.URL.Query()["client_version"]; !exists {
			version = c.Request.Header.Get("version")
		}
		if len(version) > 100 {
			cxError(c, http.StatusBadRequest, "invalid_client_version", "Invalid client_version")
			return false
		}
	}
	return true
}

// cxPrepareResponses validates full-history input and preserves the caller's JSON/SSE choice.
// NormalizeRequest describes the upstream payload, where CX always uses SSE; the native
// handler still needs stream:false to aggregate that SSE into a JSON response.
func (s *Server) cxPrepareResponses(c *gin.Context, targeted bool) bool {
	if !targeted && s.pluginHost != nil && s.pluginHost.HasModelRouters() {
		return true
	}
	path := c.Request.URL.Path
	if c.Request.Method != http.MethodPost || (path != "/v1/responses" && path != "/v1/responses/compact") {
		return true
	}
	body, err := cxcompat.ReadRequest(c.Writer, c.Request)
	if err != nil {
		cxRequestError(c, err)
		return false
	}
	if !targeted {
		var model string
		if json.Unmarshal(body.Fields["model"], &model) != nil || !cxRegisteredCodexModel(model) {
			c.Request.Body = io.NopCloser(bytes.NewReader(body.Raw))
			return true
		}
	}
	compact := path == "/v1/responses/compact"
	normalized, err := cxcompat.NormalizeRequest(body.Fields, compact)
	if err != nil {
		cxRequestError(c, err)
		return false
	}
	if !compact {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(normalized, &fields); err != nil {
			cxRequestError(c, err)
			return false
		}
		if stream, exists := body.Fields["stream"]; exists {
			fields["stream"] = stream
		}
		normalized, err = json.Marshal(fields)
		if err != nil {
			cxRequestError(c, err)
			return false
		}
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(normalized))
	c.Request.ContentLength = int64(len(normalized))
	return true
}

// Unknown, mixed-provider, and plugin-only model routes retain native semantics.
func cxRegisteredCodexModel(model string) bool {
	baseModel := thinking.ParseSuffix(model).ModelName
	providers := util.GetProviderName(util.ResolveAutoModel(baseModel))
	if len(providers) == 0 {
		return false
	}
	for _, provider := range providers {
		if provider != "codex" {
			return false
		}
	}
	return true
}

func cxRequestError(c *gin.Context, err error) {
	var requestErr *cxcompat.RequestError
	if errors.As(err, &requestErr) {
		cxError(c, requestErr.Status, "invalid_request", requestErr.Message)
		return
	}
	cxError(c, http.StatusInternalServerError, "normalization_failed", "Could not normalize request")
}
