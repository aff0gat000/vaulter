package rules

import (
	"regexp"
	"strings"
)

// Finding describes a flagged issue in a vault secret.
type Finding struct {
	Path     string
	Key      string
	Value    string
	Rule     string
	Severity string // "warning" or "error"
}

// Rule checks a key-value pair and returns a finding description or empty string.
type Rule struct {
	Name     string
	Severity string
	Check    func(path, key, value string) bool
}

// DefaultRules returns built-in rules for detecting non-secret / config-like data.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:     "config-like-key",
			Severity: "warning",
			Check: func(_, key, _ string) bool {
				lower := strings.ToLower(key)
				configKeys := []string{
					"host", "hostname", "port", "endpoint", "url",
					"region", "environment", "env", "namespace",
					"log_level", "loglevel", "debug", "verbose",
					"timeout", "retry", "retries", "max_connections",
					"version", "app_name", "service_name",
				}
				for _, ck := range configKeys {
					if lower == ck {
						return true
					}
				}
				return false
			},
		},
		{
			Name:     "boolean-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				v := strings.ToLower(strings.TrimSpace(value))
				return v == "true" || v == "false" || v == "yes" || v == "no"
			},
		},
		{
			Name:     "numeric-only-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				v := strings.TrimSpace(value)
				if v == "" {
					return false
				}
				matched, _ := regexp.MatchString(`^\d+$`, v)
				return matched
			},
		},
		{
			Name:     "empty-value",
			Severity: "error",
			Check: func(_, _, value string) bool {
				return strings.TrimSpace(value) == ""
			},
		},
		{
			Name:     "placeholder-value",
			Severity: "error",
			Check: func(_, _, value string) bool {
				v := strings.ToLower(strings.TrimSpace(value))
				placeholders := []string{
					"changeme", "todo", "fixme", "replace_me",
					"xxx", "placeholder", "default", "example",
					"your_", "insert_", "<change",
				}
				for _, p := range placeholders {
					if strings.Contains(v, p) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:     "large-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				return len(value) > 10000
			},
		},
		{
			Name:     "json-blob",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				v := strings.TrimSpace(value)
				return (strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}")) ||
					(strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]"))
			},
		},
		{
			Name:     "base64-config",
			Severity: "warning",
			Check: func(_, key, _ string) bool {
				lower := strings.ToLower(key)
				return strings.Contains(lower, "config") && strings.Contains(lower, "base64")
			},
		},
	}
}
