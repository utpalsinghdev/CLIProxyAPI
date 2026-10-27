package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const (
	cxModelsExecutionModel = "cx/models"
	cxModelsRawCatalogKey  = "cx_models_raw_catalog"
)

// handleCXModels uses the canonical CX OAuth store only when explicitly configured.
func (s *Server) handleCXModels(c *gin.Context) {
	home := strings.TrimSpace(s.cfg.CXCompatibility.SourceHome)
	if !s.cfg.CXCompatibility.Enabled || home == "" {
		return
	}
	if !filepath.IsAbs(home) || s.cfg.Home.Enabled || s.handlers == nil || s.handlers.AuthManager == nil {
		cxError(c, http.StatusUnauthorized, "auth_unavailable", "No stored OAuth account can authenticate")
		return
	}
	store := cxcompat.NewStore(home)
	accounts, err := store.ListOAuthAccounts()
	if err != nil || len(accounts) == 0 {
		cxError(c, http.StatusUnauthorized, "auth_unavailable", "No stored OAuth account can authenticate")
		return
	}
	active, activeErr := store.ActiveAccount()
	if activeErr != nil {
		cxError(c, http.StatusUnauthorized, "auth_unavailable", "No stored OAuth account can authenticate")
		return
	}
	ordered := make([]cxcompat.AccountSnapshot, 0, len(accounts))
	if active != nil {
		for _, account := range accounts {
			if account.Email == active.Email {
				ordered = append(ordered, account)
				break
			}
		}
	}
	for _, account := range accounts {
		if active == nil || account.Email != active.Email {
			ordered = append(ordered, account)
		}
	}
	s.cxAccounts.mu.Lock()
	if _, exists := s.handlers.AuthManager.Executor("codex"); !exists {
		s.handlers.AuthManager.RegisterExecutor(executor.NewCodexAutoExecutor(s.cfg))
	}
	s.cxAccounts.mu.Unlock()
	auths, err := s.cxAccounts.reconcile(s.handlers.AuthManager, home, ordered)
	if err != nil || len(auths) == 0 {
		cxError(c, http.StatusUnauthorized, "auth_unavailable", "No stored OAuth account can authenticate")
		return
	}
	plan := coreauth.RequestAuthPlan{
		Auths: auths, Model: cxModelsExecutionModel, AllowFallback: cxcompat.AllowFallback,
		RetryLimit: s.cfg.RequestRetry, AllowRetry: cxcompat.AllowModelRetry,
	}
	ctx := coreauth.WithRequestAuthPlan(c.Request.Context(), plan)
	values, explicit := c.Request.URL.Query()["client_version"]
	version := "0.163.0"
	if explicit {
		if len(values) > 0 {
			version = values[0]
		}
	} else if header := c.GetHeader("version"); header != "" {
		version = header
	}
	if len(version) > 100 {
		cxError(c, http.StatusBadRequest, "invalid_client_version", "Invalid client_version")
		return
	}
	query := make(map[string][]string, 1)
	query["client_version"] = []string{version}
	opts := coreexecutor.Options{
		Alt: "cx/models", Headers: c.Request.Header.Clone(), Query: query,
		SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI,
		Metadata: map[string]any{
			coreexecutor.GenerateMetadataKey: false,
			cxModelsRawCatalogKey:            explicit,
		},
	}
	response, err := s.handlers.AuthManager.Execute(ctx, []string{"codex"}, coreexecutor.Request{Model: cxModelsExecutionModel}, opts)
	if err != nil {
		writeCXModelsError(c, err)
		return
	}
	for name, values := range response.Headers {
		lower := strings.ToLower(name)
		if lower == "retry-after" || lower == "x-request-id" || lower == "openai-processing-ms" || strings.HasPrefix(lower, "x-codex-") || strings.HasPrefix(lower, "x-ratelimit-") {
			for _, value := range values {
				c.Writer.Header().Add(name, value)
			}
		}
	}
	payload := response.Payload
	if !explicit {
		payload, err = mergeCXProviderModels(payload)
		if err != nil {
			writeCXModelsError(c, err)
			return
		}
	}
	c.Data(http.StatusOK, "application/json", payload)
}

// Keep Codex CLI's versioned catalog unchanged, but expose all configured providers
// to OpenAI-compatible clients and the management dashboard.
func mergeCXProviderModels(raw []byte) ([]byte, error) {
	var catalog struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(catalog.Data))
	for _, item := range catalog.Data {
		var model struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(item, &model); err != nil {
			return nil, err
		}
		seen[model.ID] = true
	}
	added := false
	for _, model := range registry.GetGlobalRegistry().GetAvailableModels("openai") {
		id, _ := model["id"].(string)
		if id == "" || seen[id] || cxRegisteredCodexModel(id) {
			continue
		}
		item, err := json.Marshal(model)
		if err != nil {
			return nil, err
		}
		catalog.Data = append(catalog.Data, item)
		seen[id] = true
		added = true
	}
	if !added {
		return raw, nil
	}
	return json.Marshal(catalog)
}

func writeCXModelsError(c *gin.Context, err error) {
	status := http.StatusBadGateway
	var statusErr interface{ StatusCode() int }
	if errors.As(err, &statusErr) {
		status = statusErr.StatusCode()
	}
	if status < 400 || status > 599 {
		status = http.StatusBadGateway
	}
	var upstreamHeaders interface{ Headers() http.Header }
	if errors.As(err, &upstreamHeaders) {
		for name, values := range upstreamHeaders.Headers() {
			lower := strings.ToLower(name)
			if lower == "retry-after" || lower == "x-request-id" || lower == "openai-processing-ms" || strings.HasPrefix(lower, "x-codex-") || strings.HasPrefix(lower, "x-ratelimit-") {
				for _, value := range values {
					c.Writer.Header().Add(name, value)
				}
			}
		}
	}
	message := "Codex model catalog request failed"
	if err != nil {
		message = err.Error()
		var payload struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal([]byte(message), &payload) == nil {
			if payload.Error.Message != "" {
				message = payload.Error.Message
			} else if payload.Detail != "" {
				message = payload.Detail
			}
		}
		if len(message) > 2000 {
			message = message[:2000]
		}
	}
	typ := "server_error"
	if status == http.StatusUnauthorized {
		typ = "authentication_error"
	} else if status < 500 && status != http.StatusTooManyRequests {
		typ = "invalid_request_error"
	} else if status == http.StatusTooManyRequests {
		typ = "rate_limit_error"
	}
	c.JSON(status, gin.H{"error": gin.H{"message": message, "type": typ, "code": nil}})
}
