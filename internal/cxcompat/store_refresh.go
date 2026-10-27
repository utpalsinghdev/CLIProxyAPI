package cxcompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	tokenEndpoint = "https://auth.openai.com/oauth/token"
	clientID      = "app_EMoamEEZ73f0CkXaXp7hrann"
)

// EnsureAuth returns a valid stored OAuth auth snapshot, refreshing under the CX lock when needed.
func (s *Store) EnsureAuth(ctx context.Context, email string, force bool, failedAccessToken string) (AuthSnapshot, error) {
	if email == "" || strings.IndexByte(email, 0) >= 0 {
		return AuthSnapshot{}, errors.New("invalid account identity")
	}
	_, initial, err := s.readRaw(email)
	if err != nil {
		return AuthSnapshot{}, err
	}
	if !isOAuth(initial) {
		return AuthSnapshot{}, errors.New("stored account is not OAuth")
	}
	access := initial.Auth.Tokens.Access
	if failedAccessToken != "" && access != failedAccessToken {
		return snapshot(initial).Auth, nil
	}
	if !force && !expired(access, time.Now()) {
		return snapshot(initial).Auth, nil
	}
	var result AuthSnapshot
	err = s.withAccountLock(ctx, email, func() error {
		_, current, err := s.readRaw(email)
		if err != nil {
			return err
		}
		if !isOAuth(current) {
			return errors.New("stored account is not OAuth")
		}
		currentAccess := current.Auth.Tokens.Access
		if failedAccessToken != "" && currentAccess != failedAccessToken {
			result = snapshot(current).Auth
			return nil
		}
		if !force && !expired(currentAccess, time.Now()) {
			result = snapshot(current).Auth
			return nil
		}
		accessToken, refreshToken, idToken, exchangeErr := s.exchange(ctx, current.Auth.Tokens.Refresh)
		if exchangeErr != nil {
			return errors.New("could not refresh stored OAuth account")
		}
		if accessToken == "" || refreshToken == "" || idToken == "" {
			return errors.New("token refresh response is invalid")
		}

		latestRaw, latest, err := s.readRaw(email)
		if err != nil {
			return err
		}
		if !isOAuth(latest) {
			return errors.New("stored account is not OAuth")
		}
		if latest.Auth.Tokens.Access != currentAccess || latest.Auth.Tokens.Refresh != current.Auth.Tokens.Refresh ||
			latest.Auth.Tokens.ID != current.Auth.Tokens.ID || latest.Auth.Tokens.Account != current.Auth.Tokens.Account {
			result = snapshot(latest).Auth
			return nil
		}
		if err := replaceTokens(latestRaw, accessToken, refreshToken, idToken); err != nil {
			return errors.New("stored account could not be updated")
		}
		var auth map[string]json.RawMessage
		if json.Unmarshal(latestRaw["auth"], &auth) != nil || auth == nil {
			return errors.New("stored account could not be updated")
		}
		lastRefresh, err := json.Marshal(time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return errors.New("stored account could not be updated")
		}
		auth["last_refresh"] = lastRefresh
		authRaw, err := json.Marshal(auth)
		if err != nil {
			return errors.New("stored account could not be updated")
		}
		if err := replaceTopLevel(latestRaw, "auth", authRaw); err != nil {
			return errors.New("stored account could not be updated")
		}
		encoded, err := json.MarshalIndent(latestRaw, "", "  ")
		if err != nil {
			return errors.New("stored account could not be updated")
		}
		if err := atomicWrite(accountPath(s.accountsDir(), email), encoded); err != nil {
			return errors.New("stored account could not be updated")
		}
		_, saved, err := s.readRaw(email)
		if err != nil {
			return errors.New("stored account could not be updated")
		}
		result = snapshot(saved).Auth
		return nil
	})
	if err != nil {
		return AuthSnapshot{}, err
	}
	return result, nil
}

func replaceTokens(account map[string]json.RawMessage, access, refresh, id string) error {
	var auth map[string]json.RawMessage
	if json.Unmarshal(account["auth"], &auth) != nil || auth == nil {
		return errors.New("invalid auth object")
	}
	var tokens map[string]json.RawMessage
	if json.Unmarshal(auth["tokens"], &tokens) != nil || tokens == nil {
		return errors.New("invalid token object")
	}
	for key, value := range map[string]string{"access_token": access, "refresh_token": refresh, "id_token": id} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		tokens[key] = encoded
	}
	encodedTokens, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	auth["tokens"] = encodedTokens
	encodedAuth, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	account["auth"] = encodedAuth
	return nil
}

func replaceTopLevel(account map[string]json.RawMessage, key string, value []byte) error {
	if !json.Valid(value) {
		return errors.New("invalid account data")
	}
	account[key] = append(json.RawMessage(nil), value...)
	return nil
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".cx-refresh-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func exchangeOpenAIToken(ctx context.Context, refreshToken string) (string, string, string, error) {
	requestBody, err := json.Marshal(map[string]string{
		"client_id": clientID, "grant_type": "refresh_token", "refresh_token": refreshToken,
	})
	if err != nil {
		return "", "", "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(requestBody))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024)); _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("token endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		return "", "", "", errors.New("invalid token response")
	}
	var issued struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
	}
	if json.Unmarshal(data, &issued) != nil || issued.Access == "" || issued.Refresh == "" || issued.ID == "" {
		return "", "", "", errors.New("invalid token response")
	}
	return issued.Access, issued.Refresh, issued.ID, nil
}
