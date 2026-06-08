// SPDX-License-Identifier: Apache-2.0

// Package report renders vaulter search/audit results as shareable HTML or
// Markdown documents — useful for publishing as CI artifacts or for review by
// people who don't live in a terminal.
package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	texttemplate "text/template"

	"github.com/aff0gat000/vaulter/pkg/vaulter"
)

// Data is the input to a report renderer.
type Data struct {
	Command   string            // "audit" or "search"
	Mount     string            // KV mount that was scanned
	Prefix    string            // path prefix that was scanned
	Scanned   int               // number of secrets scanned
	Matches   []vaulter.Match   // search matches (search reports)
	Findings  []vaulter.Finding // audit findings (audit reports)
	Generated time.Time         // generation time; omitted when zero
}

// view is the template-facing model with derived fields.
type view struct {
	Data
	Errors      int
	Warnings    int
	GeneratedAt string
}

func severityRank(s string) int {
	switch s {
	case "error":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

func newView(d Data) view {
	// Sort findings: errors first, then by path, then key, for stable output.
	findings := make([]vaulter.Finding, len(d.Findings))
	copy(findings, d.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Key < findings[j].Key
	})
	d.Findings = findings

	v := view{Data: d}
	for _, f := range findings {
		switch f.Severity {
		case "error":
			v.Errors++
		case "warning":
			v.Warnings++
		}
	}
	if !d.Generated.IsZero() {
		v.GeneratedAt = d.Generated.UTC().Format(time.RFC3339)
	}
	return v
}

// mdCell escapes a value for use inside a Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

var markdownTmpl = texttemplate.Must(texttemplate.New("md").Funcs(texttemplate.FuncMap{
	"mdCell": mdCell,
}).Parse(`# Vaulter {{.Command}} report
{{if .GeneratedAt}}
_Generated {{.GeneratedAt}}_
{{end}}
- Mount: ` + "`{{.Mount}}`" + `
- Prefix: ` + "`{{if .Prefix}}{{.Prefix}}{{else}}(root){{end}}`" + `
- Secrets scanned: {{.Scanned}}

## Summary

| Severity | Count |
|----------|-------|
| error | {{.Errors}} |
| warning | {{.Warnings}} |
| matches | {{len .Matches}} |
{{if .Findings}}
## Findings

| Severity | Rule | Path | Key | Value |
|----------|------|------|-----|-------|
{{range .Findings}}| {{.Severity}} | {{.Rule}} | {{mdCell .Path}} | {{mdCell .Key}} | {{mdCell .Value}} |
{{end}}{{end}}{{if .Matches}}
## Matches

| Path | Key | Value |
|------|-----|-------|
{{range .Matches}}| {{mdCell .Path}} | {{mdCell .Key}} | {{mdCell .Value}} |
{{end}}{{end}}{{if and (not .Findings) (not .Matches)}}
No results.
{{end}}`))

var htmlTmpl = template.Must(template.New("html").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vaulter {{.Command}} report</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
  th { background: #f4f4f5; }
  td.error { color: #b00020; font-weight: 600; }
  td.warning { color: #8a6d00; font-weight: 600; }
  code { background: #f4f4f5; padding: 0.1rem 0.3rem; border-radius: 3px; }
</style>
</head>
<body>
<h1>Vaulter {{.Command}} report</h1>
<div class="meta">
  {{if .GeneratedAt}}Generated {{.GeneratedAt}} &middot; {{end}}
  Mount <code>{{.Mount}}</code> &middot;
  Prefix <code>{{if .Prefix}}{{.Prefix}}{{else}}(root){{end}}</code> &middot;
  {{.Scanned}} secrets scanned
</div>

<h2>Summary</h2>
<table>
  <tr><th>Severity</th><th>Count</th></tr>
  <tr><td class="error">error</td><td>{{.Errors}}</td></tr>
  <tr><td class="warning">warning</td><td>{{.Warnings}}</td></tr>
  <tr><td>matches</td><td>{{len .Matches}}</td></tr>
</table>

{{if .Findings}}
<h2>Findings</h2>
<table>
  <tr><th>Severity</th><th>Rule</th><th>Path</th><th>Key</th><th>Value</th></tr>
  {{range .Findings}}<tr>
    <td class="{{.Severity}}">{{.Severity}}</td>
    <td>{{.Rule}}</td><td>{{.Path}}</td><td>{{.Key}}</td><td>{{.Value}}</td>
  </tr>{{end}}
</table>
{{end}}

{{if .Matches}}
<h2>Matches</h2>
<table>
  <tr><th>Path</th><th>Key</th><th>Value</th></tr>
  {{range .Matches}}<tr><td>{{.Path}}</td><td>{{.Key}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{end}}

{{if and (not .Findings) (not .Matches)}}<p>No results.</p>{{end}}
</body>
</html>
`))

// Markdown writes a Markdown report to w.
func Markdown(w io.Writer, d Data) error {
	return markdownTmpl.Execute(w, newView(d))
}

// HTML writes a self-contained HTML report to w. Values are HTML-escaped.
func HTML(w io.Writer, d Data) error {
	return htmlTmpl.Execute(w, newView(d))
}
