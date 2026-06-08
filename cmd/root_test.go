// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aff0gat000/vaulter/pkg/vaulter"
)

func TestNewRootCmd_Flags(t *testing.T) {
	cmd := NewRootCmd()

	flags := []string{"mount", "kv-version", "prefix", "json", "insecure", "timeout", "show-values"}
	for _, f := range flags {
		if cmd.PersistentFlags().Lookup(f) == nil {
			t.Errorf("missing persistent flag: %s", f)
		}
	}
}

func TestNewRootCmd_Subcommands(t *testing.T) {
	cmd := NewRootCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"search", "audit"} {
		if !names[want] {
			t.Errorf("missing subcommand: %s", want)
		}
	}
}

func TestNewRootCmd_Version(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Version == "" {
		t.Error("version should be set")
	}
}

func TestSearchCmd_RequiresKeyOrValue(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no --key or --value given")
	}
}

func TestRunRequiresVaultAddr(t *testing.T) {
	os.Unsetenv("VAULT_ADDR")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "test"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when VAULT_ADDR is not set")
	}
}

func TestRunRequiresVaultToken(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	os.Unsetenv("VAULT_TOKEN")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "test"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	if err := cmd.Execute(); err == nil {
		t.Error("expected error when VAULT_TOKEN is not set")
	}
}

func TestSearchCmd_PathTraversal(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	t.Setenv("VAULT_TOKEN", "test-token")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "test", "--prefix", "../escape"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestAuditCmd_RequiresVaultAddr(t *testing.T) {
	os.Unsetenv("VAULT_ADDR")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"audit"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when VAULT_ADDR is not set")
	}
}

func newMockVault() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"myapp"},
			},
		})
	})
	mux.HandleFunc("/v1/secret/data/myapp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"password": "s3cret",
					"host":     "localhost",
				},
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestSearchCmd_Integration(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "pass", "--insecure", "--show-values"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	output := buf.String()
	if !strings.Contains(output, "password") {
		t.Errorf("expected 'password' in output, got: %s", output)
	}
}

func TestSearchCmd_JSON(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "pass", "--insecure", "--json"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if _, ok := result["secrets_scanned"]; !ok {
		t.Error("expected 'secrets_scanned' in JSON output")
	}
}

func TestAuditCmd_Integration(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"audit", "--insecure"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	output := buf.String()
	if !strings.Contains(output, "config-like-key") {
		t.Errorf("expected 'config-like-key' finding, got: %s", output)
	}
}

func TestAuditCmd_MarkdownFormat(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"audit", "--insecure", "--format", "markdown"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := cmd.Execute()
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, "# Vaulter audit report") {
		t.Errorf("expected markdown report header, got: %s", out)
	}
	if !strings.Contains(out, "config-like-key") {
		t.Errorf("expected config-like-key finding in markdown, got: %s", out)
	}
}

func TestAuditCmd_HTMLFormat(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"audit", "--insecure", "--format", "html"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := cmd.Execute()
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
		t.Errorf("expected HTML document, got: %s", buf.String())
	}
}

func TestCmd_UnknownFormat(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"audit", "--insecure", "--format", "xml"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for unknown --format")
	}
}

func TestGate(t *testing.T) {
	findings := []vaulter.Finding{
		{Severity: "error", Rule: "empty-value"},
		{Severity: "warning", Rule: "config-like-key"},
	}
	tests := []struct {
		failOn   string
		findings []vaulter.Finding
		wantGate bool
		wantErr  bool // non-gate (invalid value) error
	}{
		{"none", findings, false, false},
		{"", findings, false, false},
		{"error", findings, true, false},
		{"warning", findings, true, false},
		{"error", []vaulter.Finding{{Severity: "warning"}}, false, false},
		{"warning", []vaulter.Finding{{Severity: "warning"}}, true, false},
		{"error", nil, false, false},
		{"bogus", findings, false, true},
	}
	for _, tt := range tests {
		err := gate(&Config{FailOn: tt.failOn}, tt.findings, len(tt.findings))
		var ge *gateError
		gotGate := errors.As(err, &ge)
		if gotGate != tt.wantGate {
			t.Errorf("gate(failOn=%q) gate=%v, want %v (err=%v)", tt.failOn, gotGate, tt.wantGate, err)
		}
		gotErr := err != nil && !gotGate
		if gotErr != tt.wantErr {
			t.Errorf("gate(failOn=%q) otherErr=%v, want %v (err=%v)", tt.failOn, gotErr, tt.wantErr, err)
		}
	}
}

func TestAuditCmd_JSONLowercaseSeverity(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"audit", "--insecure", "--json"})

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := cmd.Execute()
	w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	var result struct {
		Findings []struct {
			Severity string `json:"severity"`
			Rule     string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings in JSON output")
	}
	for _, f := range result.Findings {
		if f.Severity == "" || f.Rule == "" {
			t.Errorf("expected lowercase severity/rule JSON keys, got %+v", f)
		}
	}
}

func TestSearchCmd_NoResults(t *testing.T) {
	srv := newMockVault()
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "nonexistent_xyz", "--insecure"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSearchCmd_MountPathTraversal(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	t.Setenv("VAULT_TOKEN", "test-token")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "test", "--mount", "../evil"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for mount path traversal")
	}
}

func TestSearchCmd_InvalidKVVersion(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	t.Setenv("VAULT_TOKEN", "test-token")
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"search", "--key", "test", "--kv-version", "3"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid kv version")
	}
}
