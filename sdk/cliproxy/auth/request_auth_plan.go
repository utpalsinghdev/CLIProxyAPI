package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type requestAuthPlanContextKey struct{}

// RequestAuthPlan freezes the ordered credentials available to one request.
type RequestAuthPlan struct {
	Auths         []*Auth
	Model         string
	AllowFallback func(error) bool
}

// WithRequestAuthPlan returns a context carrying an independent snapshot of plan auths.
func WithRequestAuthPlan(ctx context.Context, plan RequestAuthPlan) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	copyPlan := plan
	copyPlan.Auths = make([]*Auth, 0, len(plan.Auths))
	for _, auth := range plan.Auths {
		if auth != nil {
			copyPlan.Auths = append(copyPlan.Auths, auth.Clone())
		}
	}
	return context.WithValue(ctx, requestAuthPlanContextKey{}, copyPlan)
}

// RequestAuthPlanFromContext returns a defensive copy of the request plan, if present.
func RequestAuthPlanFromContext(ctx context.Context) (RequestAuthPlan, bool) {
	if ctx == nil {
		return RequestAuthPlan{}, false
	}
	plan, ok := ctx.Value(requestAuthPlanContextKey{}).(RequestAuthPlan)
	if !ok {
		return RequestAuthPlan{}, false
	}
	copyPlan := plan
	copyPlan.Auths = make([]*Auth, 0, len(plan.Auths))
	for _, auth := range plan.Auths {
		if auth != nil {
			copyPlan.Auths = append(copyPlan.Auths, auth.Clone())
		}
	}
	return copyPlan, true
}

func (m *Manager) executeRequestAuthPlan(ctx context.Context, plan RequestAuthPlan, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if pinned := pinnedAuthIDFromMetadata(opts.Metadata); pinned != "" {
		for _, auth := range plan.Auths {
			if auth.ID == pinned {
				plan.Auths = []*Auth{auth}
				break
			}
		}
		if len(plan.Auths) != 1 || plan.Auths[0].ID != pinned {
			return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "pinned auth is not in request plan"}
		}
	}
	var lastErr error
	var cooledErr error
	for _, snapshot := range plan.Auths {
		if ctx != nil && ctx.Err() != nil {
			return cliproxyexecutor.Response{}, ctx.Err()
		}
		if snapshot == nil || !strings.EqualFold(strings.TrimSpace(snapshot.Provider), "codex") {
			return cliproxyexecutor.Response{}, &Error{Code: "invalid_request_auth_plan", Message: "request auth plan accepts Codex auths only"}
		}
		auth := snapshot.Clone()
		if _, registered := m.GetByID(auth.ID); !registered {
			return cliproxyexecutor.Response{}, &Error{Code: "invalid_request_auth_plan", Message: "request auth plan contains an unregistered auth"}
		}
		if m.requestPlanAuthCooling(snapshot, plan.Model) {
			if cooledErr == nil {
				cooledErr = m.requestPlanCooldownError(plan.Auths)
			}
			continue
		}
		executor, ok := m.Executor(executorKeyFromAuth(auth))
		if !ok {
			return cliproxyexecutor.Response{}, &Error{Code: "executor_not_found", Message: "Codex executor not registered"}
		}
		publishSelectedAuthMetadata(opts.Metadata, auth)
		attemptCtx := newUpstreamAttemptContext(ctx)
		if rt := m.roundTripperFor(auth); rt != nil {
			attemptCtx = context.WithValue(attemptCtx, roundTripperContextKey{}, rt)
			attemptCtx = context.WithValue(attemptCtx, "cliproxy.roundtripper", rt)
		}
		execReq := req
		execReq.Model = plan.Model
		execOpts := opts
		if execOpts.RequestAfterAuthInterceptor != nil {
			var err error
			execReq, execOpts, err = applyRequestAfterAuthInterceptor(attemptCtx, executor, "codex", execReq, execOpts, plan.Model)
			if err != nil {
				lastErr = err
				if plan.AllowFallback == nil || !plan.AllowFallback(err) {
					return cliproxyexecutor.Response{}, err
				}
				continue
			}
		}
		if preparer, ok := executor.(RequestAuthPreparer); ok && preparer.ShouldPrepareRequestAuth(auth) {
			prepared, errPrepare := preparer.PrepareRequestAuth(attemptCtx, auth.Clone())
			if errPrepare != nil {
				m.MarkResult(attemptCtx, Result{AuthID: auth.ID, Provider: "codex", Model: plan.Model, RouteModel: plan.Model, Error: resultErrorFromError(errPrepare), Options: execOpts, SkipQuotaObservation: true})
				lastErr = errPrepare
				if plan.AllowFallback == nil || !plan.AllowFallback(errPrepare) {
					return cliproxyexecutor.Response{}, errPrepare
				}
				continue
			}
			if prepared != nil {
				auth = prepared
			}
		}
		start := newUpstreamAttemptContext(attemptCtx)
		response, err := executor.Execute(start, auth, execReq, execOpts)
		if err != nil && isUnauthorizedError(err) {
			if refreshed, ok := m.refreshRequestPlanAuth(newUpstreamAttemptContext(attemptCtx), executor, auth); ok {
				response, err = executor.Execute(newUpstreamAttemptContext(attemptCtx), refreshed, execReq, execOpts)
				auth = refreshed
			}
		}
		if err == nil {
			m.clearPlannedAuthBlock(auth)
			m.MarkResult(attemptCtx, Result{AuthID: auth.ID, Provider: "codex", Model: plan.Model, RouteModel: plan.Model, Success: true, Options: execOpts})
			return response, nil
		}
		m.recordRequestPlanResult(attemptCtx, auth, Result{AuthID: auth.ID, Provider: "codex", Model: plan.Model, RouteModel: plan.Model, Error: resultErrorFromError(err), RetryAfter: retryAfterFromError(err), CredentialScope: isCredentialScopedError(err), Options: execOpts}, err)
		lastErr = err
		if plan.AllowFallback == nil || !plan.AllowFallback(err) {
			return cliproxyexecutor.Response{}, err
		}
	}
	if lastErr != nil {
		return cliproxyexecutor.Response{}, lastErr
	}
	if cooledErr != nil {
		return cliproxyexecutor.Response{}, cooledErr
	}
	return cliproxyexecutor.Response{}, &Error{Code: "auth_not_found", Message: "no auth available in request plan"}
}

func (m *Manager) executeStreamRequestAuthPlan(ctx context.Context, plan RequestAuthPlan, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if pinned := pinnedAuthIDFromMetadata(opts.Metadata); pinned != "" {
		for _, auth := range plan.Auths {
			if auth.ID == pinned {
				plan.Auths = []*Auth{auth}
				break
			}
		}
		if len(plan.Auths) != 1 || plan.Auths[0].ID != pinned {
			return nil, &Error{Code: "auth_not_found", Message: "pinned auth is not in request plan"}
		}
	}
	var lastErr error
	var cooledErr error
	for _, snapshot := range plan.Auths {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if snapshot == nil || !strings.EqualFold(strings.TrimSpace(snapshot.Provider), "codex") {
			return nil, &Error{Code: "invalid_request_auth_plan", Message: "request auth plan accepts Codex auths only"}
		}
		auth := snapshot.Clone()
		if _, registered := m.GetByID(auth.ID); !registered {
			return nil, &Error{Code: "invalid_request_auth_plan", Message: "request auth plan contains an unregistered auth"}
		}
		if m.requestPlanAuthCooling(snapshot, plan.Model) {
			if cooledErr == nil {
				cooledErr = m.requestPlanCooldownError(plan.Auths)
			}
			continue
		}
		executor, ok := m.Executor(executorKeyFromAuth(auth))
		if !ok {
			return nil, &Error{Code: "executor_not_found", Message: "Codex executor not registered"}
		}
		publishSelectedAuthMetadata(opts.Metadata, auth)
		execReq := req
		execReq.Model = plan.Model
		streamOpts := opts
		streamOpts.Stream = true
		streamCtx := newUpstreamAttemptContext(ctx)
		if rt := m.roundTripperFor(auth); rt != nil {
			streamCtx = context.WithValue(streamCtx, roundTripperContextKey{}, rt)
			streamCtx = context.WithValue(streamCtx, "cliproxy.roundtripper", rt)
		}
		if streamOpts.RequestAfterAuthInterceptor != nil {
			var interceptErr error
			execReq, streamOpts, interceptErr = applyRequestAfterAuthInterceptor(streamCtx, executor, "codex", execReq, streamOpts, plan.Model)
			if interceptErr != nil {
				lastErr = interceptErr
				if plan.AllowFallback == nil || !plan.AllowFallback(interceptErr) {
					return nil, interceptErr
				}
				continue
			}
		}
		if preparer, ok := executor.(RequestAuthPreparer); ok && preparer.ShouldPrepareRequestAuth(auth) {
			prepared, errPrepare := preparer.PrepareRequestAuth(streamCtx, auth.Clone())
			if errPrepare != nil {
				m.MarkResult(streamCtx, Result{AuthID: auth.ID, Provider: "codex", Model: plan.Model, RouteModel: plan.Model, Error: resultErrorFromError(errPrepare), Options: streamOpts, SkipQuotaObservation: true})
				lastErr = errPrepare
				if plan.AllowFallback == nil || !plan.AllowFallback(errPrepare) {
					return nil, errPrepare
				}
				continue
			}
			if prepared != nil {
				auth = prepared
			}
		}
		stream, err := executor.ExecuteStream(streamCtx, auth, execReq, streamOpts)

		if err != nil && isUnauthorizedError(err) {
			if refreshed, refreshedOK := m.refreshRequestPlanAuth(newUpstreamAttemptContext(streamCtx), executor, auth); refreshedOK {
				stream, err = executor.ExecuteStream(newUpstreamAttemptContext(streamCtx), refreshed, execReq, streamOpts)
				auth = refreshed
			}
		}
		if err == nil && stream != nil {
			first, bootstrapErr := firstStreamPayload(ctx, stream.Chunks)
			if bootstrapErr == nil {
				stream.Chunks = recordRequestPlanStream(ctx, m, auth, plan.Model, streamOpts, first, stream.Chunks)
				return stream, nil
			}
			err = bootstrapErr
		}
		if err == nil {
			err = fmt.Errorf("Codex executor returned nil stream")
		}
		m.recordRequestPlanResult(streamCtx, auth, Result{AuthID: auth.ID, Provider: "codex", Model: plan.Model, RouteModel: plan.Model, Error: resultErrorFromError(err), RetryAfter: retryAfterFromError(err), CredentialScope: isCredentialScopedError(err), Options: streamOpts}, err)
		lastErr = err
		if plan.AllowFallback == nil || !plan.AllowFallback(err) {
			return nil, err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if cooledErr != nil {
		return nil, cooledErr
	}
	return nil, &Error{Code: "auth_not_found", Message: "no auth available in request plan"}
}

func (m *Manager) refreshRequestPlanAuth(ctx context.Context, executor ProviderExecutor, attempted *Auth) (*Auth, bool) {
	if m == nil || executor == nil || attempted == nil || !authHasRefreshCredential(attempted) || ctx == nil || ctx.Err() != nil {
		return attempted, false
	}
	lockValue, _ := m.refreshLocks.LoadOrStore(attempted.ID, &authRefreshLock{})
	lock, _ := lockValue.(*authRefreshLock)
	if lock == nil {
		return attempted, false
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if ctx.Err() != nil {
		return attempted, false
	}

	m.mu.RLock()
	current := m.auths[attempted.ID]
	if current != nil {
		current = current.Clone()
	}
	m.mu.RUnlock()
	if current == nil || current.RegistrationEpoch != attempted.RegistrationEpoch {
		return attempted, false
	}
	refreshed, err := executor.Refresh(ctx, attempted.Clone())
	if err != nil || refreshed == nil || ctx.Err() != nil {
		return attempted, false
	}
	refreshed.ID = attempted.ID
	refreshed.Provider = attempted.Provider
	if refreshed.Runtime == nil {
		refreshed.Runtime = attempted.Runtime
	}
	refreshed.LastRefreshedAt = time.Now()
	refreshed.NextRefreshAfter = time.Time{}
	refreshed.LastError = nil
	refreshed.StatusMessage = ""
	refreshed.Unavailable = false
	refreshed.Status = StatusActive
	updated, err := m.UpdateRefreshedAuth(ctx, current, refreshed)
	if err != nil || updated == nil {
		return attempted, false
	}
	return updated, true
}

func (m *Manager) recordRequestPlanResult(ctx context.Context, auth *Auth, result Result, err error) {
	if auth != nil {
		m.recordPlannedAuthFailure(auth, err)
	}
	m.recordAvailabilityNeutralResult(ctx, result)
}

func (m *Manager) requestPlanCooldownError(auths []*Auth) error {
	return m.plannedCooldownError(auths)
}

func (m *Manager) requestPlanAuthCooling(snapshot *Auth, _ string) bool {
	if m == nil || snapshot == nil || snapshot.ID == "" {
		return false
	}
	value, ok := m.requestPlanBlocks.Load(snapshot.ID)
	if !ok {
		return false
	}
	block, ok := value.(plannedAuthBlock)
	if !ok {
		m.requestPlanBlocks.Delete(snapshot.ID)
		return false
	}
	if block.registrationEpoch != snapshot.RegistrationEpoch || (block.reason == plannedAuthBlockAuth && block.fingerprint != accessTokenFingerprint(snapshot)) {
		m.requestPlanBlocks.CompareAndDelete(snapshot.ID, block)
		return false
	}
	if !block.until.After(time.Now()) {
		m.requestPlanBlocks.CompareAndDelete(snapshot.ID, block)
		return false
	}
	return true
}

func firstStreamPayload(ctx context.Context, chunks <-chan cliproxyexecutor.StreamChunk) ([]cliproxyexecutor.StreamChunk, error) {
	buffered := make([]cliproxyexecutor.StreamChunk, 0, 1)
	for chunks != nil {
		var chunk cliproxyexecutor.StreamChunk
		var ok bool
		if ctx == nil {
			chunk, ok = <-chunks
		} else {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case chunk, ok = <-chunks:
			}
		}
		if !ok {
			break
		}
		if chunk.Err != nil {
			return nil, chunk.Err
		}
		buffered = append(buffered, chunk)
		if len(chunk.Payload) > 0 {
			return buffered, nil
		}
	}
	return buffered, nil
}

func recordRequestPlanStream(ctx context.Context, m *Manager, auth *Auth, model string, opts cliproxyexecutor.Options, first []cliproxyexecutor.StreamChunk, source <-chan cliproxyexecutor.StreamChunk) <-chan cliproxyexecutor.StreamChunk {
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		failed := false
		forward := func(chunk cliproxyexecutor.StreamChunk) bool {
			if chunk.Err != nil && !failed {
				failed = true
				m.recordRequestPlanResult(ctx, auth, Result{AuthID: auth.ID, Provider: "codex", Model: model, RouteModel: model, Error: resultErrorFromError(chunk.Err), RetryAfter: retryAfterFromError(chunk.Err), CredentialScope: isCredentialScopedError(chunk.Err), Options: opts}, chunk.Err)
			}
			select {
			case out <- chunk:
				return true
			case <-ctx.Done():
				return false
			}
		}
		for _, chunk := range first {
			if !forward(chunk) {
				return
			}
		}
		for chunk := range source {
			if !forward(chunk) {
				return
			}
		}
		if !failed {
			m.clearPlannedAuthBlock(auth)
			m.MarkResult(ctx, Result{AuthID: auth.ID, Provider: "codex", Model: model, RouteModel: model, Success: true, Options: opts})
		}
	}()
	return out
}
