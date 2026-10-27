// Package cxcompat preserves CX's Codex proxy contracts for staged migrations.
package cxcompat

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const RequestBodyLimit = 16 << 20

// RequestError is safe to return to clients. It never contains request data.
type RequestError struct {
	Status  int
	Message string
}

func (e *RequestError) Error() string { return e.Message }

// RequestBody retains original bytes so non-Codex routes can pass through unchanged.
type RequestBody struct {
	Fields map[string]json.RawMessage
	Raw    []byte
}

// ReadRequest accepts one uncompressed JSON object with CX's request-size limit.
func ReadRequest(w http.ResponseWriter, req *http.Request) (RequestBody, error) {
	if encoding := req.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return RequestBody{}, &RequestError{http.StatusUnsupportedMediaType, "Unsupported content encoding; send uncompressed JSON"}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, RequestBodyLimit))
	if err != nil {
		var limitErr *http.MaxBytesError
		if errors.As(err, &limitErr) {
			return RequestBody{}, &RequestError{http.StatusRequestEntityTooLarge, "Request body exceeds 16 MiB limit"}
		}
		return RequestBody{}, &RequestError{http.StatusBadRequest, "Invalid request body"}
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return RequestBody{}, &RequestError{http.StatusBadRequest, "Request body must be valid JSON"}
	}
	if object == nil {
		return RequestBody{}, &RequestError{http.StatusBadRequest, "Request body must be a JSON object"}
	}
	return RequestBody{Fields: object, Raw: body}, nil
}

// NormalizeRequest applies CX's full-history Responses contract without inspecting credentials.
// Returned bytes are a new value; callers retain their original input unchanged.
func NormalizeRequest(body map[string]json.RawMessage, compact bool) ([]byte, error) {
	var model string
	if json.Unmarshal(body["model"], &model) != nil || strings.TrimSpace(model) == "" {
		return nil, requiredInputError()
	}
	var inputString string
	var input []json.RawMessage
	if json.Unmarshal(body["input"], &inputString) == nil && string(body["input"]) != "null" {
		wrapped, err := json.Marshal(map[string]any{
			"role": "user", "content": []map[string]string{{"type": "input_text", "text": inputString}},
		})
		if err != nil {
			return nil, err
		}
		input = []json.RawMessage{wrapped}
	} else if json.Unmarshal(body["input"], &input) != nil || input == nil {
		return nil, requiredInputError()
	}
	if previous, ok := body["previous_response_id"]; ok && string(previous) != "null" {
		return nil, &RequestError{http.StatusBadRequest, "Send full conversation history, not previous_response_id"}
	}
	instructions, ok := body["instructions"]
	if !ok {
		instructions = json.RawMessage(`""`)
	} else {
		var value string
		if string(instructions) == "null" || json.Unmarshal(instructions, &value) != nil {
			return nil, &RequestError{http.StatusBadRequest, "instructions must be a string"}
		}
	}
	if stream, ok := body["stream"]; ok {
		var value bool
		if string(stream) == "null" || json.Unmarshal(stream, &value) != nil {
			return nil, &RequestError{http.StatusBadRequest, "stream must be a boolean"}
		}
	}
	out := make(map[string]json.RawMessage, len(body)+4)
	for key, value := range body {
		out[key] = value
	}
	for i, item := range input {
		var object map[string]json.RawMessage
		if json.Unmarshal(item, &object) != nil || object == nil {
			continue
		}
		var role string
		if json.Unmarshal(object["role"], &role) == nil && role == "system" {
			object["role"] = json.RawMessage(`"developer"`)
			normalized, err := json.Marshal(object)
			if err != nil {
				return nil, err
			}
			input[i] = normalized
		}
	}
	encodedInput, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	out["input"] = encodedInput
	out["instructions"] = instructions
	if !compact {
		out["stream"] = json.RawMessage(`true`)
		out["store"] = json.RawMessage(`false`)
		include := []string{}
		var values []json.RawMessage
		if json.Unmarshal(body["include"], &values) == nil {
			seen := make(map[string]bool)
			for _, value := range values {
				var entry string
				if string(value) != "null" && json.Unmarshal(value, &entry) == nil && !seen[entry] {
					include = append(include, entry)
					seen[entry] = true
				}
			}
		}
		found := false
		for _, entry := range include {
			found = found || entry == "reasoning.encrypted_content"
		}
		if !found {
			include = append(include, "reasoning.encrypted_content")
		}
		encodedInclude, err := json.Marshal(include)
		if err != nil {
			return nil, err
		}
		out["include"] = encodedInclude
		if parallel, ok := out["parallel_tool_calls"]; !ok || string(parallel) == "null" {
			out["parallel_tool_calls"] = json.RawMessage(`true`)
		}
	} else {
		delete(out, "stream")
		delete(out, "store")
	}
	for _, key := range []string{
		"max_output_tokens", "max_completion_tokens", "temperature", "top_p", "truncation", "user",
		"prompt_cache_retention", "prompt_cache_options", "stream_options", "background", "safety_identifier", "previous_response_id",
	} {
		delete(out, key)
	}
	return json.Marshal(out)
}

func requiredInputError() *RequestError {
	return &RequestError{http.StatusBadRequest, "A model string and input string or array are required"}
}
