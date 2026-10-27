package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

const (
	cxModelsResponseLimit         = 32 << 20
	cxModelsRawCatalogMetadataKey = "cx_models_raw_catalog"
)

type cxModelsHTTPError struct {
	code    int
	message string
	headers http.Header
}

func (e cxModelsHTTPError) Error() string        { return e.message }
func (e cxModelsHTTPError) StatusCode() int      { return e.code }
func (e cxModelsHTTPError) Headers() http.Header { return e.headers.Clone() }

func newCXModelsHTTPError(code int, message string, headers http.Header) cxModelsHTTPError {
	return cxModelsHTTPError{code: code, message: message, headers: headers.Clone()}
}

func (e *CodexExecutor) executeCXModels(ctx context.Context, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if !isCXAccountAuth(auth) || auth.Attributes[cxRuntimeOnlyAttribute] != "true" {
		return cliproxyexecutor.Response{}, statusErr{code: http.StatusUnauthorized, msg: "codex executor: CX credentials are unavailable"}
	}
	token, _ := auth.Metadata["access_token"].(string)
	if strings.TrimSpace(token) == "" {
		return cliproxyexecutor.Response{}, statusErr{code: http.StatusUnauthorized, msg: "codex executor: CX credentials are unavailable"}
	}
	version := "0.163.0"
	if values, ok := opts.Query["client_version"]; ok && len(values) > 0 {
		version = values[0]
	}
	if len(version) > 100 {
		return cliproxyexecutor.Response{}, statusErr{code: http.StatusBadRequest, msg: "Invalid client_version"}
	}
	endpoint := "https://chatgpt.com/backend-api/codex/models?" + url.Values{"client_version": []string{version}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex executor: create CX model request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	for _, name := range []string{
		"user-agent", "originator", "version", "session_id", "session-id", "thread-id",
		"x-client-request-id", "x-codex-turn-metadata", "x-codex-turn-state",
		"x-codex-beta-features", "x-codex-routing-hint", "openai-beta",
	} {
		if value := opts.Headers.Get(name); value != "" {
			request.Header.Set(name, value)
		}
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "cx/0.2.1")
	}
	accountID, _ := auth.Metadata["account_id"].(string)
	if accountID == "" {
		if idToken, _ := auth.Metadata["id_token"].(string); idToken != "" {
			if claims, err := codexauth.ParseJWTToken(idToken); err == nil {
				accountID = claims.GetAccountID()
			}
		}
	}
	if accountID != "" {
		request.Header.Set("chatgpt-account-id", accountID)
	}

	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	response, err := httpClient.Do(request)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	defer func() {
		if errClose := response.Body.Close(); errClose != nil {
			log.Errorf("codex executor: close CX model response body error: %v", errClose)
		}
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, errRead := io.ReadAll(io.LimitReader(response.Body, 2049))
		if errRead != nil {
			return cliproxyexecutor.Response{}, errRead
		}
		if len(body) > 2048 {
			body = body[:2048]
		}
		return cliproxyexecutor.Response{}, newCXModelsHTTPError(response.StatusCode, string(body), response.Header)
	}
	body, errRead := io.ReadAll(io.LimitReader(response.Body, cxModelsResponseLimit+1))
	if errRead != nil {
		return cliproxyexecutor.Response{}, errRead
	}
	if len(body) > cxModelsResponseLimit {
		return cliproxyexecutor.Response{}, newCXModelsHTTPError(http.StatusBadGateway, "Codex model catalog exceeded size limit", response.Header)
	}
	var catalog struct {
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil || catalog.Models == nil {
		return cliproxyexecutor.Response{}, newCXModelsHTTPError(http.StatusBadGateway, "Invalid Codex model catalog", response.Header)
	}
	if opts.Metadata[cxModelsRawCatalogMetadataKey] == true {
		return cliproxyexecutor.Response{Payload: body, Headers: response.Header.Clone()}, nil
	}
	payload, err := cxModelsListPayload(body)
	if err != nil {
		return cliproxyexecutor.Response{}, newCXModelsHTTPError(http.StatusBadGateway, "Invalid Codex model catalog", response.Header)
	}
	return cliproxyexecutor.Response{Payload: payload, Headers: response.Header.Clone()}, nil
}

func cxModelsListPayload(raw []byte) ([]byte, error) {
	var payload struct {
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Models == nil {
		return nil, errors.New("invalid Codex model catalog")
	}
	type model struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	data := make([]model, 0, len(payload.Models))
	for _, rawModel := range payload.Models {
		var item struct {
			Slug string `json:"slug"`
		}
		if json.Unmarshal(rawModel, &item) == nil && item.Slug != "" {
			data = append(data, model{ID: item.Slug, Object: "model", OwnedBy: "openai"})
		}
	}
	return json.Marshal(struct {
		Object string  `json:"object"`
		Data   []model `json:"data"`
	}{Object: "list", Data: data})
}
