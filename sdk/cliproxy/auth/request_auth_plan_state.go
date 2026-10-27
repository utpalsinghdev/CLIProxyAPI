package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const requestPlanErrorBodyLimit = 1 << 20

type plannedAuthBlockReason uint8

const (
	plannedAuthBlockAuth plannedAuthBlockReason = iota + 1
	plannedAuthBlockQuota
)

type plannedAuthBlock struct {
	until             time.Time
	registrationEpoch uint64
	reason            plannedAuthBlockReason
	fingerprint       [32]byte
	err               *Error
}

func accessTokenFingerprint(auth *Auth) [32]byte {
	if auth == nil {
		return sha256.Sum256(nil)
	}
	token := auth.Attributes["access_token"]
	if token == "" && auth.Metadata != nil {
		token, _ = auth.Metadata["access_token"].(string)
	}
	return sha256.Sum256([]byte(token))
}

func (m *Manager) clearPlannedAuthBlock(auth *Auth) {
	if auth == nil || auth.ID == "" {
		return
	}
	value, ok := m.requestPlanBlocks.Load(auth.ID)
	if !ok {
		return
	}
	block, ok := value.(plannedAuthBlock)
	if ok && block.registrationEpoch == auth.RegistrationEpoch && block.reason == plannedAuthBlockAuth && block.fingerprint == accessTokenFingerprint(auth) {
		m.requestPlanBlocks.CompareAndDelete(auth.ID, block)
	}
}

func (m *Manager) recordPlannedAuthFailure(auth *Auth, err error) {
	status := statusCodeFromError(err)
	reason := plannedAuthBlockReason(0)
	duration := 60 * time.Second
	if status == http.StatusUnauthorized {
		reason = plannedAuthBlockAuth
	} else if status == http.StatusTooManyRequests && quotaErrorInChain(err) {
		reason = plannedAuthBlockQuota
		if retry := retryAfterFromError(err); retry != nil && *retry > 0 {
			duration = *retry
		} else if seconds := quotaResetSeconds(err); seconds > 0 {
			duration = time.Duration(seconds) * time.Second
		}
	}
	if reason == 0 || auth == nil || auth.ID == "" {
		return
	}
	m.requestPlanBlocks.Store(auth.ID, plannedAuthBlock{
		until:             time.Now().Add(duration),
		registrationEpoch: auth.RegistrationEpoch,
		reason:            reason,
		fingerprint:       accessTokenFingerprint(auth),
		err:               sanitizedPlanError(err, auth),
	})
}

func quotaErrorInChain(err error) bool {
	var bodyProvider interface{ ResponseBody() []byte }
	if !errors.As(err, &bodyProvider) || bodyProvider == nil {
		return false
	}
	body := bodyProvider.ResponseBody()
	if len(body) == 0 || len(body) > requestPlanErrorBodyLimit {
		return false
	}
	var payload any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	return containsUsageLimitReached(payload, 0)
}

func containsUsageLimitReached(value any, depth int) bool {
	if depth > 12 {
		return false
	}
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if (key == "type" || key == "code") && child == "usage_limit_reached" {
				return true
			}
			if containsUsageLimitReached(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if containsUsageLimitReached(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func quotaResetSeconds(err error) int64 {
	var bodyProvider interface{ ResponseBody() []byte }
	if !errors.As(err, &bodyProvider) || bodyProvider == nil {
		return 0
	}
	body := bodyProvider.ResponseBody()
	if len(body) == 0 || len(body) > requestPlanErrorBodyLimit {
		return 0
	}
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return 0
	}
	return quotaResetSecondsInValue(payload, 0)
}

func quotaResetSecondsInValue(value any, depth int) int64 {
	if depth > 12 {
		return 0
	}
	switch item := value.(type) {
	case map[string]any:
		for _, key := range []string{"resets_in_seconds", "resets_at"} {
			if number, ok := item[key].(float64); ok && number > 0 {
				if key == "resets_at" {
					number -= float64(time.Now().Unix())
				}
				if number > 0 {
					return int64(number + 0.999)
				}
			}
		}
		for _, child := range item {
			if seconds := quotaResetSecondsInValue(child, depth+1); seconds > 0 {
				return seconds
			}
		}
	case []any:
		for _, child := range item {
			if seconds := quotaResetSecondsInValue(child, depth+1); seconds > 0 {
				return seconds
			}
		}
	}
	return 0
}

func sanitizedPlanError(err error, auth *Auth) *Error {
	result := resultErrorFromError(err)
	if result == nil {
		return nil
	}
	message := result.Message
	if token := auth.Attributes["access_token"]; token != "" {
		message = strings.ReplaceAll(message, token, "[redacted]")
	}
	if auth.Metadata != nil {
		if token, ok := auth.Metadata["access_token"].(string); ok && token != "" {
			message = strings.ReplaceAll(message, token, "[redacted]")
		}
	}
	result.Message = message
	return result
}

func (m *Manager) plannedCooldownError(auths []*Auth) error {
	var earliest time.Time
	var anyQuota bool
	var original *Error
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		value, ok := m.requestPlanBlocks.Load(auth.ID)
		if !ok {
			continue
		}
		block, ok := value.(plannedAuthBlock)
		if !ok || block.registrationEpoch != auth.RegistrationEpoch || (block.reason == plannedAuthBlockAuth && block.fingerprint != accessTokenFingerprint(auth)) || !block.until.After(time.Now()) {
			continue
		}
		if block.reason == plannedAuthBlockQuota {
			anyQuota = true
		}
		if earliest.IsZero() || block.until.Before(earliest) {
			earliest = block.until
		}
		if original == nil && block.err != nil {
			original = cloneError(block.err)
		}
	}
	if earliest.IsZero() {
		return &Error{Code: "auth_not_found", Message: "no auth available in request plan"}
	}
	status := http.StatusUnauthorized
	code, message := "auth_unavailable", "No stored OAuth account can authenticate. Re-add ended sessions with cx add --device-auth."
	if anyQuota {
		status, code, message = http.StatusTooManyRequests, "quota_exceeded", "Stored Codex accounts are unavailable until their quota resets"
	}
	if original != nil && !anyQuota {
		message = original.Message
	}
	return &plannedCooldownError{base: &Error{Code: code, Message: message, HTTPStatus: status}, retryAfter: max(time.Second, time.Until(earliest))}
}

type plannedCooldownError struct {
	base       *Error
	retryAfter time.Duration
}

func (e *plannedCooldownError) Error() string {
	return fmt.Sprintf("%s: %s", e.base.Code, e.base.Message)
}
func (e *plannedCooldownError) StatusCode() int { return e.base.HTTPStatus }
func (e *plannedCooldownError) MarshalJSON() ([]byte, error) {
	errorType := "authentication_error"
	if e.base.HTTPStatus == http.StatusTooManyRequests {
		errorType = "rate_limit_error"
	}
	return json.Marshal(struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}{Error: struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	}{Message: e.base.Message, Type: errorType, Code: e.base.Code}})
}
func (e *plannedCooldownError) RetryAfter() *time.Duration { value := e.retryAfter; return &value }
func (e *plannedCooldownError) Headers() http.Header {
	return http.Header{"Retry-After": []string{strconv.Itoa(int((e.retryAfter + time.Second - 1) / time.Second))}}
}
