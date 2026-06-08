// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/aff0gat000/vaulter/internal/rules"
	"github.com/aff0gat000/vaulter/internal/vault"
)

func TestNew_InvalidKeyRegex(t *testing.T) {
	_, err := New(Options{KeyPattern: "[invalid"})
	if err == nil {
		t.Fatal("expected error for invalid key regex")
	}
}

func TestNew_InvalidValueRegex(t *testing.T) {
	_, err := New(Options{ValuePattern: "[invalid"})
	if err == nil {
		t.Fatal("expected error for invalid value regex")
	}
}

func TestNew_PatternTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxPatternLength+1)
	_, err := New(Options{KeyPattern: long})
	if err == nil {
		t.Fatal("expected error for too-long key pattern")
	}
	_, err = New(Options{ValuePattern: long})
	if err == nil {
		t.Fatal("expected error for too-long value pattern")
	}
}

func TestNew_ValidPatterns(t *testing.T) {
	s, err := New(Options{KeyPattern: "test", ValuePattern: "val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.keyRe == nil || s.valueRe == nil {
		t.Fatal("expected compiled regexps")
	}
}

func TestProcess_KeyMatch(t *testing.T) {
	s, _ := New(Options{KeyPattern: "pass", ShowValues: true})
	result := s.Process(vault.Secret{
		Path: "app/db",
		Data: map[string]interface{}{"password": "secret123", "host": "localhost"},
	})
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(result.Matches))
	}
	if result.Matches[0].Key != "password" {
		t.Errorf("expected key 'password', got %q", result.Matches[0].Key)
	}
}

func TestProcess_ValueMatch(t *testing.T) {
	s, _ := New(Options{ValuePattern: "prod", ShowValues: true})
	result := s.Process(vault.Secret{
		Path: "app/db",
		Data: map[string]interface{}{"url": "prod.example.com", "port": "5432"},
	})
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(result.Matches))
	}
	if result.Matches[0].Key != "url" {
		t.Errorf("expected key 'url', got %q", result.Matches[0].Key)
	}
}

func TestNew_ExplicitRules(t *testing.T) {
	s, err := New(Options{Rules: rules.DefaultRules()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.rules) == 0 {
		t.Fatal("expected explicit rules to be set")
	}
}

func TestProcess_Audit(t *testing.T) {
	s, _ := New(Options{Audit: true})
	result := s.Process(vault.Secret{
		Path: "app/config",
		Data: map[string]interface{}{"host": "localhost", "password": "real-secret"},
	})
	found := false
	for _, f := range result.Findings {
		if f.Key == "host" && f.Rule == "config-like-key" {
			found = true
		}
	}
	if !found {
		t.Error("expected config-like-key finding for 'host'")
	}
}

func TestProcess_Combined(t *testing.T) {
	s, _ := New(Options{KeyPattern: "pass", Audit: true, ShowValues: true})
	result := s.Process(vault.Secret{
		Path: "app/db",
		Data: map[string]interface{}{"password": "changeme"},
	})
	if len(result.Matches) == 0 {
		t.Error("expected search match")
	}
	if len(result.Findings) == 0 {
		t.Error("expected audit findings")
	}
}

func TestProcess_MaskedValues(t *testing.T) {
	s, _ := New(Options{KeyPattern: "pass", ShowValues: false})
	result := s.Process(vault.Secret{
		Path: "app/db",
		Data: map[string]interface{}{"password": "supersecret"},
	})
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(result.Matches))
	}
	if result.Matches[0].Value != "********" {
		t.Errorf("expected masked value, got %q", result.Matches[0].Value)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		max      int
		expected string
	}{
		{"short", 120, "short"},
		{strings.Repeat("a", 130), 120, strings.Repeat("a", 120) + "..."},
		{"line1\nline2", 120, "line1\\nline2"},
		{"", 120, ""},
		// MaxTruncate cap
		{strings.Repeat("b", 20000), 20000, strings.Repeat("b", MaxTruncate) + "..."},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input[:min(len(tt.input), 20)], tt.max, got[:min(len(got), 30)], tt.expected[:min(len(tt.expected), 30)])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
