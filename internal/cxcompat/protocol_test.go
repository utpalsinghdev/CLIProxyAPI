package cxcompat

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeRequest(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		compact bool
		want    string
	}{
		{"string input", `{"model":"gpt-6-luna","input":"hello","stream":false}`, false,
			`{"model":"gpt-6-luna","instructions":"","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}],"stream":true,"store":false,"include":["reasoning.encrypted_content"],"parallel_tool_calls":true}`},
		{"history and tool calls", `{"model":"gpt-6-luna","input":[{"role":"system","content":"rules"},{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"ok"}],"reasoning":{"effort":"high"},"include":["reasoning.encrypted_content",5,"extra","extra"],"parallel_tool_calls":false}`, false,
			`{"model":"gpt-6-luna","instructions":"","input":[{"role":"developer","content":"rules"},{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"ok"}],"reasoning":{"effort":"high"},"stream":true,"store":false,"include":["reasoning.encrypted_content","extra"],"parallel_tool_calls":false}`},
		{"compact omits transport flags", `{"model":"gpt-6-luna","input":[],"stream":false,"store":true,"instructions":"rules","max_output_tokens":50,"temperature":0,"previous_response_id":null}`, true,
			`{"model":"gpt-6-luna","input":[],"instructions":"rules"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tt.body), &body); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			got, err := NormalizeRequest(body, tt.compact)
			if err != nil {
				t.Fatal(err)
			}
			var gotValue, wantValue any
			if err := json.Unmarshal(got, &gotValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.want), &wantValue); err != nil {
				t.Fatal(err)
			}
			gotJSON, _ := json.Marshal(gotValue)
			wantJSON, _ := json.Marshal(wantValue)
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("got %s, want %s", gotJSON, wantJSON)
			}
			after, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("normalization mutated caller's input")
			}
		})
	}
}

func TestNormalizeRequestRejectsInvalidHistory(t *testing.T) {
	for _, raw := range []string{
		`{"input":""}`, `{"model":" ","input":[]}`, `{"model":"gpt-6-luna"}`,
		`{"model":"gpt-6-luna","input":null}`, `{"model":"gpt-6-luna","input":{}}`,
		`{"model":"gpt-6-luna","input":"","previous_response_id":"resp_1"}`,
		`{"model":"gpt-6-luna","input":"","instructions":null}`,
		`{"model":"gpt-6-luna","input":"","stream":"false"}`,
		`{"model":"gpt-6-luna","input":"","stream":null}`,
	} {
		var body map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatal(err)
		}
		_, err := NormalizeRequest(body, false)
		var requestErr *RequestError
		if !errors.As(err, &requestErr) || requestErr.Status != http.StatusBadRequest {
			t.Errorf("expected client error for %s, got %v", raw, err)
		}
	}
}

func TestReadRequest(t *testing.T) {
	tests := []struct {
		name, body, encoding string
		status               int
	}{
		{"valid", `{"model":"gpt-6-luna","input":""}`, "identity", 0},
		{"broken", `{`, "", 400},
		{"trailing object", `{} {}`, "", 400},
		{"array", `[]`, "", 400},
		{"null", `null`, "", 400},
		{"encoding", `{}`, "gzip", 415},
		{"oversize", strings.Repeat("x", RequestBodyLimit+1), "", 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(tt.body))
			req.Header.Set("Content-Encoding", tt.encoding)
			_, err := ReadRequest(httptest.NewRecorder(), req)
			if tt.status == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var requestErr *RequestError
			if !errors.As(err, &requestErr) || requestErr.Status != tt.status {
				t.Fatalf("got %v, want HTTP %d", err, tt.status)
			}
		})
	}
}
