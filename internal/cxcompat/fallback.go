package cxcompat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// AllowFallback matches CX's pre-response credential fallback policy. The native
// manager calls this after its one same-account 401 refresh attempt has ended.
// Transport uncertainty, ordinary rate limits, and arbitrary upstream failures stop.
func AllowFallback(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) {
		return false
	}
	if status.StatusCode() == http.StatusUnauthorized {
		return true
	}
	if status.StatusCode() != http.StatusTooManyRequests {
		return false
	}
	// Native executor errors retain the upstream JSON body as their message.
	// Never accept a substring match: policy errors can mention quota strings.
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if quotaErrorJSON(cause.Error()) {
			return true
		}
	}
	return false
}

func quotaErrorJSON(raw string) bool {
	if len(raw) > 1<<20 {
		return false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &value) != nil {
		return false
	}
	for range 4 {
		if nested, ok := value["response"]; ok {
			var next map[string]json.RawMessage
			if json.Unmarshal(nested, &next) == nil && next != nil {
				value = next
				continue
			}
		}
		if nested, ok := value["error"]; ok {
			var next map[string]json.RawMessage
			if json.Unmarshal(nested, &next) == nil && next != nil {
				value = next
				continue
			}
		}
		var kind string
		return json.Unmarshal(value["type"], &kind) == nil && kind == "usage_limit_reached"
	}
	return false
}
