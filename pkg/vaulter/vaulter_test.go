package vaulter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockVault returns an httptest server emulating a KV v2 engine with a single
// secret under secret/myapp containing a real secret plus config-like data.
func mockVault(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"keys": []string{"myapp"}},
		})
	})
	mux.HandleFunc("/v1/secret/data/myapp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"password": "s3cret",
					"db_host":  "db.internal",
					"debug":    "true",
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := New(Config{
		Address:  addr,
		Token:    "test-token",
		Mount:    "secret",
		Insecure: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew_Defaults(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	c, err := New(Config{Token: "x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want 30s", c.timeout)
	}
}

func TestNew_InvalidMount(t *testing.T) {
	_, err := New(Config{Mount: "../escape"})
	if err == nil {
		t.Fatal("expected error for path traversal mount")
	}
}

func TestNew_InvalidKVVersion(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	_, err := New(Config{KVVersion: 7})
	if err == nil {
		t.Fatal("expected error for invalid kv version")
	}
}

func TestSearch_KeyMatch(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	matches, scanned, err := c.Search(context.Background(), "", SearchOptions{
		KeyPattern: "pass", ShowValues: true,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if scanned != 1 {
		t.Errorf("scanned = %d, want 1", scanned)
	}
	if len(matches) != 1 || matches[0].Key != "password" {
		t.Fatalf("expected one password match, got %+v", matches)
	}
	if matches[0].Value != "s3cret" {
		t.Errorf("value = %q, want s3cret (ShowValues=true)", matches[0].Value)
	}
}

func TestSearch_Masked(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	matches, _, err := c.Search(context.Background(), "", SearchOptions{KeyPattern: "pass"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 1 || matches[0].Value != "********" {
		t.Fatalf("expected masked value, got %+v", matches)
	}
}

func TestSearch_InvalidPattern(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	_, _, err := c.Search(context.Background(), "", SearchOptions{KeyPattern: "[invalid"})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestSearch_PrefixTraversal(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	_, _, err := c.Search(context.Background(), "../escape", SearchOptions{KeyPattern: "x"})
	if err == nil {
		t.Fatal("expected error for path traversal prefix")
	}
}

func TestAudit_DefaultRules(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	findings, scanned, err := c.Audit(context.Background(), "", AuditOptions{})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if scanned != 1 {
		t.Errorf("scanned = %d, want 1", scanned)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Rule] = true
	}
	for _, want := range []string{"config-like-key", "boolean-value"} {
		if !got[want] {
			t.Errorf("expected a %q finding, got rules %v", want, got)
		}
	}
}

func TestAudit_MasksByDefaultAndShowValues(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	// Default: masked.
	masked, _, err := c.Audit(context.Background(), "", AuditOptions{})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, f := range masked {
		if f.Value != "********" {
			t.Errorf("expected masked value by default, got %q", f.Value)
		}
	}

	// ShowValues: real values present (db_host is config-like).
	shown, _, err := c.Audit(context.Background(), "", AuditOptions{ShowValues: true})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	found := false
	for _, f := range shown {
		if f.Key == "db_host" && f.Value == "db.internal" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected real db_host value with ShowValues, got %+v", shown)
	}
}

func TestAudit_CustomRules(t *testing.T) {
	srv := mockVault(t)
	c := newTestClient(t, srv.URL)

	// A custom rule that flags any key named exactly "password".
	rule := Rule{
		Name:     "has-password-key",
		Severity: "error",
		Check:    func(_, key, _ string) bool { return key == "password" },
	}
	findings, _, err := c.Audit(context.Background(), "", AuditOptions{Rules: []Rule{rule}})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "has-password-key" {
		t.Fatalf("expected one custom finding, got %+v", findings)
	}
}

func TestDefaultRules_Exported(t *testing.T) {
	if len(DefaultRules()) == 0 {
		t.Fatal("DefaultRules returned nothing")
	}
}
