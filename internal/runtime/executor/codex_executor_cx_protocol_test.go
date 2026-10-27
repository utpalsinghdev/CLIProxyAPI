package executor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/cxcompat"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestCodexCXNativeResponsesProtocolForwarding(t *testing.T) {
	payload := []byte(`{"model":"gpt-6-luna","instructions":"system prompt","input":[{"role":"system","content":[{"type":"input_text","text":"developer context"}]},{"role":"user","content":[{"type":"input_text","text":"continue"}]},{"type":"reasoning","id":"rs_1","encrypted_content":"sealed"},{"type":"assistant","type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"q\":\"x\"}"},{"type":"function_call_output","call_id":"call_1","output":"found"}],"tools":[{"type":"function","name":"lookup","description":"search","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"],"additionalProperties":false},"strict":true}],"text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false},"strict":true}},"prompt_cache_key":"caller-cache","stream":true}`)
	terminal := "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"model\":\"gpt-6-luna\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"
	var captured *http.Request
	var body string
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		captured = req.Clone(req.Context())
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(data)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(terminal)), Request: req}, nil
	}))
	auth := helps.CXAccountAuth(t.TempDir(), cxcompat.AccountSnapshot{Email: "cx@example.test", Auth: cxcompat.AuthSnapshot{Tokens: &cxcompat.TokenSet{AccessToken: "synthetic-token", AccountID: "synthetic-account"}}})
	auth.Attributes["base_url"] = "https://codex.invalid"
	result, err := NewCodexExecutor(nil).ExecuteStream(ctx, auth, cliproxyexecutor.Request{Model: "gpt-6-luna", Payload: payload}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: true, Headers: http.Header{"Session-Id": {"caller-session"}}})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error = %v", chunk.Err)
		}
	}
	if captured == nil {
		t.Fatal("upstream request was not captured")
	}
	if captured.URL.String() != "https://codex.invalid/responses" {
		t.Fatalf("upstream URL = %q", captured.URL)
	}
	for path, want := range map[string]string{
		"model": "gpt-6-luna", "instructions": "system prompt", "input.0.role": "developer",
		"input.0.content.0.text": "developer context", "input.2.encrypted_content": "sealed",
		"input.3.call_id": "call_1", "input.3.name": "lookup", "input.3.arguments": `{"q":"x"}`,
		"input.4.call_id": "call_1", "input.4.output": "found", "tools.0.name": "lookup",
		"tools.0.strict": "true", "text.format.type": "json_schema", "text.format.strict": "true",
		"prompt_cache_key": "caller-cache",
	} {
		if got := gjson.Get(body, path).String(); got != want {
			t.Errorf("upstream %s = %q, want %q; body=%s", path, got, want, body)
		}
	}
	if captured.Header.Get("Session-Id") != "caller-session" {
		t.Errorf("Session-Id = %q, want caller-provided value", captured.Header.Get("Session-Id"))
	}
	if captured.Header.Get("Authorization") != "Bearer synthetic-token" {
		t.Errorf("authorization = %q", captured.Header.Get("Authorization"))
	}
	if !gjson.Get(body, `include.#(=="reasoning.encrypted_content")`).Exists() {
		t.Errorf("missing reasoning inclusion in upstream body: %s", body)
	}
}

func TestCodexCXNativeResponsesStreamRequiresTerminalEvent(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "failure", body: `data: {"type":"response.failed","response":{"id":"resp_1","error":{"message":"rejected"}}}` + "\\n\\n"},
		{name: "missing terminal", body: `data: {"type":"response.created","response":{"id":"resp_1"}}` + "\\n\\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: req}, nil
			}))
			auth := helps.CXAccountAuth(t.TempDir(), cxcompat.AccountSnapshot{Email: "cx@example.test", Auth: cxcompat.AuthSnapshot{Tokens: &cxcompat.TokenSet{AccessToken: "synthetic-token"}}})
			auth.Attributes["base_url"] = "https://codex.invalid"
			result, err := NewCodexExecutor(nil).ExecuteStream(ctx, auth, cliproxyexecutor.Request{Model: "gpt-6-luna", Payload: []byte(`{"model":"gpt-6-luna","input":"hello"}`)}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: true})
			if err != nil {
				t.Fatalf("ExecuteStream() error = %v", err)
			}
			var streamErr error
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					streamErr = chunk.Err
				}
			}
			if streamErr == nil {
				t.Fatal("stream ended without surfacing upstream failure")
			}
			if calls != 1 {
				t.Fatalf("upstream request count = %d, want 1", calls)
			}
		})
	}
}
