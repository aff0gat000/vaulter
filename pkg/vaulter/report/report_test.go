package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/yb/vaulter/pkg/vaulter"
)

func sampleAudit() Data {
	return Data{
		Command: "audit",
		Mount:   "secret",
		Prefix:  "apps/",
		Scanned: 3,
		Findings: []vaulter.Finding{
			{Path: "apps/b", Key: "debug", Value: "true", Rule: "boolean-value", Severity: "warning"},
			{Path: "apps/a", Key: "pwd", Value: "changeme", Rule: "placeholder-value", Severity: "error"},
		},
		Generated: time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
	}
}

func TestMarkdown_Audit(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, sampleAudit()); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"# Vaulter audit report",
		"_Generated 2026-05-31T12:00:00Z_",
		"| error | 1 |",
		"| warning | 1 |",
		"placeholder-value",
		"boolean-value",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, out)
		}
	}

	// Errors must be sorted ahead of warnings.
	if strings.Index(out, "placeholder-value") > strings.Index(out, "boolean-value") {
		t.Error("expected error-severity finding to sort before warning")
	}
}

func TestMarkdown_EscapesPipes(t *testing.T) {
	var buf bytes.Buffer
	d := Data{
		Command: "search",
		Matches: []vaulter.Match{{Path: "p", Key: "k", Value: "a|b\nc"}},
	}
	if err := Markdown(&buf, d); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `a\|b c`) {
		t.Errorf("expected pipe-escaped, newline-flattened cell, got:\n%s", out)
	}
}

func TestMarkdown_RootPrefixAndNoResults(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, Data{Command: "audit", Mount: "secret"}); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "(root)") {
		t.Errorf("expected (root) for empty prefix, got:\n%s", out)
	}
	if !strings.Contains(out, "No results.") {
		t.Errorf("expected 'No results.', got:\n%s", out)
	}
}

func TestHTML_EscapesValues(t *testing.T) {
	var buf bytes.Buffer
	d := Data{
		Command: "search",
		Mount:   "secret",
		Matches: []vaulter.Match{{Path: "p", Key: "k", Value: "<script>alert(1)</script>"}},
	}
	if err := HTML(&buf, d); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("HTML report did not escape a value containing markup")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped value in HTML, got:\n%s", out)
	}
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("expected a full HTML document")
	}
}

func TestHTML_AuditSeverityClasses(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleAudit()); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<td class="error">error</td>`) {
		t.Errorf("expected error severity class, got:\n%s", out)
	}
}
