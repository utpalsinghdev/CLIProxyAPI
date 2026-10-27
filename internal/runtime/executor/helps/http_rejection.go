package helps

import (
	"net/http"
	"time"
)

// HTTPRejectionError distinguishes an HTTP rejection from an error embedded in a
// successful response body. A body-level failure may follow server-side tool activity.
// Unwrap preserves the provider's status, quota and retry-after classification.
type HTTPRejectionError struct {
	Err interface {
		error
		StatusCode() int
		RetryAfter() *time.Duration
		IsCredentialScoped() bool
	}
}

func (e HTTPRejectionError) Error() string { return e.Err.Error() }

func (e HTTPRejectionError) Unwrap() error { return e.Err }

func (e HTTPRejectionError) StatusCode() int { return e.Err.StatusCode() }

func (e HTTPRejectionError) RetryAfter() *time.Duration { return e.Err.RetryAfter() }

func (e HTTPRejectionError) IsCredentialScoped() bool { return e.Err.IsCredentialScoped() }

func (e HTTPRejectionError) RetryableBeforeOutput() bool {
	switch e.StatusCode() {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
