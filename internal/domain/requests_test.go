package domain

import (
	"encoding/json"
	"testing"
)

func TestRegisterRequestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	orig := RegisterRequest{
		Mode:            "temporary",
		Subdomain:       "myapp",
		User:            "admin",
		AccessMode:      "form",
		Password:        "secret",
		ClientHostname:  "workstation",
		ClientMachineID: "abc123",
		LocalPort:       "3000",
		ClientVersion:   "v1.0.0",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RegisterRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestRegisterResponseJSONKeys(t *testing.T) {
	t.Parallel()

	resp := RegisterResponse{
		TunnelID:      "t-1",
		PublicURL:     "https://myapp.example.com",
		WSURL:         "wss://example.com/v1/tunnels/connect?token=abc",
		ServerTLSMode: "auto",
		ServerVersion: "v2.0.0",
		WAFEnabled:    true,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	requiredKeys := []string{"tunnel_id", "public_url", "ws_url", "server_tls_mode", "server_version", "waf_enabled"}
	for _, key := range requiredKeys {
		if _, ok := m[key]; !ok {
			t.Fatalf("missing expected JSON key %q", key)
		}
	}
}

func TestErrorResponseOmitsEmptyCode(t *testing.T) {
	t.Parallel()

	resp := ErrorResponse{Error: "something went wrong"}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["error_code"]; ok {
		t.Fatal("expected error_code to be omitted when empty")
	}
}
