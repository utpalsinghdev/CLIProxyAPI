package cxcompat

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type fallbackFixtureError struct {
	status int
	body   string
}

func (e fallbackFixtureError) Error() string   { return e.body }
func (e fallbackFixtureError) StatusCode() int { return e.status }

func TestAllowFallback(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"none", nil, false},
		{"cancelled", fmt.Errorf("wrapped: %w", context.Canceled), false},
		{"timeout", context.DeadlineExceeded, false},
		{"network uncertainty", errors.New("connection reset"), false},
		{"unusable auth", fallbackFixtureError{401, "unauthorized"}, true},
		{"explicit quota", fallbackFixtureError{429, `{"error":{"type":"usage_limit_reached"}}`}, true},
		{"nested quota", fmt.Errorf("attempt: %w", fallbackFixtureError{429, `{"response":{"error":{"type":"usage_limit_reached"}}}`}), true},
		{"generic rate limit", fallbackFixtureError{429, `{"error":{"type":"rate_limit_error"}}`}, false},
		{"message mentions quota", fallbackFixtureError{429, `{"error":{"type":"rate_limit_error","message":"usage_limit_reached"}}`}, false},
		{"code instead of type", fallbackFixtureError{429, `{"error":{"code":"usage_limit_reached"}}`}, false},
		{"quota string not JSON", fallbackFixtureError{429, "usage_limit_reached"}, false},
		{"quota on 500", fallbackFixtureError{500, `{"error":{"type":"usage_limit_reached"}}`}, false},
		{"policy denial", fallbackFixtureError{403, `{"error":{"type":"usage_limit_reached"}}`}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := AllowFallback(tt.err); got != tt.want {
				t.Fatalf("fallback = %v, want %v", got, tt.want)
			}
		})
	}
}
