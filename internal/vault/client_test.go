package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateMountAndPrefix(t *testing.T) {
	tests := []struct {
		mount, prefix string
		wantErr       bool
	}{
		{"secret", "apps/prod", false},
		{"secret", "", false},
		{"", "", false},
		{"secret/../admin", "", true},
		{"secret", "../escape", true},
		{"/absolute", "", true},
		{"secret", "/absolute", true},
		{"secret", "a/b/c", false},
	}
	for _, tt := range tests {
		err := ValidateMountAndPrefix(tt.mount, tt.prefix)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateMountAndPrefix(%q, %q) err=%v, wantErr=%v", tt.mount, tt.prefix, err, tt.wantErr)
		}
	}
}

func TestNewClient_InvalidKVVersion(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	_, err := NewClient(ClientConfig{Mount: "secret", KVVer: 3})
	if err == nil {
		t.Fatal("expected error for kv version 3")
	}
	_, err = NewClient(ClientConfig{Mount: "secret", KVVer: 0})
	if err == nil {
		t.Fatal("expected error for kv version 0")
	}
}

func TestNewClient_InvalidMount(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	_, err := NewClient(ClientConfig{Mount: "../escape", KVVer: 2})
	if err == nil {
		t.Fatal("expected error for path traversal mount")
	}
}

func TestNewClient_Valid(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	c, err := NewClient(ClientConfig{Mount: "secret", KVVer: 2, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.mount != "secret" || c.kvVer != 2 {
		t.Error("client fields not set correctly")
	}
}

func TestListPath(t *testing.T) {
	tests := []struct {
		kvVer    int
		mount    string
		prefix   string
		expected string
	}{
		{2, "secret", "apps", "secret/metadata/apps"},
		{2, "secret", "", "secret/metadata"},
		{1, "secret", "apps", "secret/apps"},
		{1, "secret", "", "secret"},
	}
	for _, tt := range tests {
		c := &Client{mount: tt.mount, kvVer: tt.kvVer}
		got := c.listPath(tt.prefix)
		if got != tt.expected {
			t.Errorf("listPath(%q) kvVer=%d = %q, want %q", tt.prefix, tt.kvVer, got, tt.expected)
		}
	}
}

func TestWalk_WithMockServer_KV2(t *testing.T) {
	mux := http.NewServeMux()

	// LIST secret/metadata/
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "LIST" || r.URL.Query().Get("list") == "true" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"myapp"},
				},
			})
			return
		}
		w.WriteHeader(404)
	})

	// READ secret/data/myapp
	mux.HandleFunc("/v1/secret/data/myapp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"password": "s3cret",
				},
			},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	client, err := NewClient(ClientConfig{Mount: "secret", KVVer: 2, Insecure: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()
	out := make(chan Secret, 10)
	errCh := make(chan error, 1)
	go func() { errCh <- client.Walk(ctx, "", out) }()

	var secrets []Secret
	for s := range out {
		secrets = append(secrets, s)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Walk error: %v", err)
	}

	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].Path != "myapp" {
		t.Errorf("expected path 'myapp', got %q", secrets[0].Path)
	}
	if secrets[0].Data["password"] != "s3cret" {
		t.Errorf("expected password 's3cret', got %v", secrets[0].Data["password"])
	}
}

func TestWalk_PrefixValidation(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	client, err := NewClient(ClientConfig{Mount: "secret", KVVer: 2, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	out := make(chan Secret, 1)
	err = client.Walk(context.Background(), "../escape", out)
	if err == nil {
		t.Fatal("expected error for path traversal prefix in Walk")
	}
}

// Verify Client implements Walker interface
var _ Walker = (*Client)(nil)
