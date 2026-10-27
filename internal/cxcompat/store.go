// Package cxcompat reads and refreshes the canonical codex-accounts OAuth store.
package cxcompat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

const storeDirName = ".codex-accounts"

// Store is bound to an explicit home root; it never uses the process home implicitly.
type Store struct {
	home     string
	exchange tokenExchanger
}

// TokenSet contains the canonical CX OAuth fields.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	AccountID    string
}

// AuthSnapshot is an immutable-by-copy view of auth credentials.
type AuthSnapshot struct {
	Mode        string
	APIKey      string
	LastRefresh string
	Tokens      *TokenSet
}

// AccountSnapshot is an immutable-by-copy typed view. Unknown JSON stays private
// and is preserved by rereading the source file immediately before writes.
type AccountSnapshot struct {
	Email         string
	AddedAt       string
	Auth          AuthSnapshot
	ProjectID     string
	ProjectName   string
	AdminKeyLabel string
}

// NewStore creates a store rooted at home with the production OpenAI token exchange.
func NewStore(home string) *Store {
	return &Store{home: filepath.Clean(home), exchange: exchangeOpenAIToken}
}

// NewStoreWithExchange injects the credential exchange, primarily for isolated callers and tests.
func NewStoreWithExchange(home string, exchange func(context.Context, string) (access, refresh, id string, err error)) *Store {
	store := NewStore(home)
	if exchange != nil {
		store.exchange = exchange
	}
	return store
}

type tokenExchanger func(context.Context, string) (access, refresh, id string, err error)

type storedAccount struct {
	Email string `json:"email"`
	Auth  struct {
		Mode        string `json:"auth_mode"`
		APIKey      string `json:"OPENAI_API_KEY"`
		LastRefresh string `json:"last_refresh"`
		Tokens      *struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
			ID      string `json:"id_token"`
			Account string `json:"account_id"`
		} `json:"tokens"`
	} `json:"auth"`
	AddedAt       string `json:"addedAt"`
	ProjectID     string `json:"projectId"`
	ProjectName   string `json:"projectName"`
	AdminKeyLabel string `json:"adminKeyLabel"`
}

func (s *Store) accountsDir() string { return filepath.Join(s.home, storeDirName, "accounts") }
func (s *Store) activePath() string  { return filepath.Join(s.home, ".codex", "auth.json") }

func accountPath(dir, email string) string {
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._@-", r) {
			return r
		}
		return '_'
	}, email)
	return filepath.Join(dir, name+".json")
}

func (s *Store) readRaw(email string) (map[string]json.RawMessage, storedAccount, error) {
	var record storedAccount
	if s.home == "" || s.home == "." {
		return nil, record, errors.New("account store is unavailable")
	}
	path := accountPath(s.accountsDir(), email)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, record, errNotFound
		}
		return nil, record, errors.New("account store is unavailable")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil || json.Unmarshal(data, &record) != nil || record.Email != email {
		return nil, record, errors.New("account identity is invalid")
	}
	return raw, record, nil
}

var errNotFound = errors.New("account not found")

func snapshot(record storedAccount) AccountSnapshot {
	out := AccountSnapshot{Email: record.Email, AddedAt: record.AddedAt, ProjectID: record.ProjectID,
		ProjectName: record.ProjectName, AdminKeyLabel: record.AdminKeyLabel,
		Auth: AuthSnapshot{Mode: record.Auth.Mode, APIKey: record.Auth.APIKey, LastRefresh: record.Auth.LastRefresh}}
	if record.Auth.Tokens != nil {
		out.Auth.Tokens = &TokenSet{AccessToken: record.Auth.Tokens.Access, RefreshToken: record.Auth.Tokens.Refresh,
			IDToken: record.Auth.Tokens.ID, AccountID: record.Auth.Tokens.Account}
	}
	return out
}

func isOAuth(record storedAccount) bool {
	return record.Auth.Mode != "apikey" && record.Auth.APIKey == "" && record.Auth.Tokens != nil && record.Auth.Tokens.Access != "" && record.Auth.Tokens.Refresh != "" && record.Auth.Tokens.ID != ""
}

// ListOAuthAccounts lists valid OAuth records in CX's email order.
func (s *Store) ListOAuthAccounts() ([]AccountSnapshot, error) {
	if err := s.ensureDirs(); err != nil {
		return nil, errors.New("account store is unavailable")
	}
	entries, err := os.ReadDir(s.accountsDir())
	if err != nil {
		return nil, errors.New("account store is unavailable")
	}
	accounts := make([]AccountSnapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.accountsDir(), entry.Name()))
		if readErr != nil {
			continue
		}
		var record storedAccount
		if json.Unmarshal(data, &record) == nil && record.Email != "" && isOAuth(record) {
			accounts = append(accounts, snapshot(record))
		}
	}
	collator := collate.New(language.English)
	sort.Slice(accounts, func(i, j int) bool {
		return collator.CompareString(accounts[i].Email, accounts[j].Email) < 0
	})
	return accounts, nil
}

// Account reads the exact identity requested; sanitized filename aliases never match.
func (s *Store) Account(email string) (AccountSnapshot, error) {
	if email == "" || strings.IndexByte(email, 0) >= 0 {
		return AccountSnapshot{}, errors.New("invalid account identity")
	}
	_, record, err := s.readRaw(email)
	if err != nil {
		return AccountSnapshot{}, err
	}
	return snapshot(record), nil
}

// ActiveAccount rereads ~/.codex/auth.json every call and matches CX identity rules.
func (s *Store) ActiveAccount() (*AccountSnapshot, error) {
	if s.home == "" || s.home == "." {
		return nil, errors.New("active account is unavailable")
	}
	data, err := os.ReadFile(s.activePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("active account is unavailable")
	}
	var active struct {
		APIKey string `json:"OPENAI_API_KEY"`
		Tokens *struct {
			ID string `json:"id_token"`
		} `json:"tokens"`
	}
	if json.Unmarshal(data, &active) != nil {
		return nil, nil
	}
	var email string
	if active.Tokens != nil && active.Tokens.ID != "" {
		email = tokenEmail(active.Tokens.ID)
	}
	accounts, listErr := s.ListOAuthAccounts()
	if listErr != nil {
		return nil, listErr
	}
	for _, account := range accounts {
		if email != "" && account.Email == email {
			found := account
			return &found, nil
		}
	}
	if active.APIKey == "" {
		return nil, nil
	}
	all, err := s.listAll()
	if err != nil {
		return nil, err
	}
	for _, account := range all {
		if account.Auth.APIKey == active.APIKey {
			found := account
			return &found, nil
		}
	}
	return nil, nil
}

func (s *Store) listAll() ([]AccountSnapshot, error) {
	if err := s.ensureDirs(); err != nil {
		return nil, errors.New("account store is unavailable")
	}
	entries, err := os.ReadDir(s.accountsDir())
	if err != nil {
		return nil, errors.New("account store is unavailable")
	}
	out := make([]AccountSnapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(s.accountsDir(), entry.Name()))
		if readErr != nil {
			continue
		}
		var record storedAccount
		if json.Unmarshal(data, &record) == nil && record.Email != "" {
			out = append(out, snapshot(record))
		}
	}
	return out, nil
}

func (s *Store) ensureDirs() error {
	if s.home == "" || s.home == "." {
		return errors.New("invalid home root")
	}
	for _, dir := range []string{filepath.Join(s.home, storeDirName), s.accountsDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func tokenEmail(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email   string `json:"email"`
		Profile struct {
			Email string `json:"email"`
		} `json:"https://api.openai.com/profile"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	if claims.Profile.Email != "" {
		return claims.Profile.Email
	}
	return claims.Email
}

func expired(token string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil || claims.Exp == "" {
		return false
	}
	seconds, err := claims.Exp.Int64()
	if err != nil {
		return false
	}
	return seconds-now.Unix() < 60
}
