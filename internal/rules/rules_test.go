package rules

import (
	"strings"
	"testing"
)

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatal("DefaultRules returned no rules")
	}

	tests := []struct {
		rule     string
		path     string
		key      string
		value    string
		expected bool
	}{
		// config-like-key
		{"config-like-key", "app/db", "host", "secret", true},
		{"config-like-key", "app/db", "HOST", "secret", true},
		{"config-like-key", "app/db", "port", "secret", true},
		{"config-like-key", "app/db", "endpoint", "val", true},
		{"config-like-key", "app/db", "url", "val", true},
		{"config-like-key", "app/db", "region", "val", true},
		{"config-like-key", "app/db", "environment", "val", true},
		{"config-like-key", "app/db", "env", "val", true},
		{"config-like-key", "app/db", "timeout", "val", true},
		{"config-like-key", "app/db", "version", "val", true},
		{"config-like-key", "app/db", "password", "secret", false},
		{"config-like-key", "app/db", "api_key", "secret", false},
		{"config-like-key", "app/db", "", "", false},

		// boolean-value
		{"boolean-value", "", "k", "true", true},
		{"boolean-value", "", "k", "FALSE", true},
		{"boolean-value", "", "k", "yes", true},
		{"boolean-value", "", "k", "No", true},
		{"boolean-value", "", "k", " true ", true},
		{"boolean-value", "", "k", "truthy", false},
		{"boolean-value", "", "k", "secret", false},
		{"boolean-value", "", "k", "", false},

		// numeric-only-value
		{"numeric-only-value", "", "k", "42", true},
		{"numeric-only-value", "", "k", "0", true},
		{"numeric-only-value", "", "k", "123456789", true},
		{"numeric-only-value", "", "k", "12.34", false},
		{"numeric-only-value", "", "k", "abc", false},
		{"numeric-only-value", "", "k", "", false},
		{"numeric-only-value", "", "k", " 42 ", true},

		// empty-value
		{"empty-value", "", "k", "", true},
		{"empty-value", "", "k", "   ", true},
		{"empty-value", "", "k", "\t", true},
		{"empty-value", "", "k", "x", false},

		// placeholder-value
		{"placeholder-value", "", "k", "changeme", true},
		{"placeholder-value", "", "k", "TODO: set this", true},
		{"placeholder-value", "", "k", "FIXME", true},
		{"placeholder-value", "", "k", "replace_me", true},
		{"placeholder-value", "", "k", "xxx", true},
		{"placeholder-value", "", "k", "placeholder", true},
		{"placeholder-value", "", "k", "default", true},
		{"placeholder-value", "", "k", "example_value", true},
		{"placeholder-value", "", "k", "your_token_here", true},
		{"placeholder-value", "", "k", "insert_value", true},
		{"placeholder-value", "", "k", "<change this>", true},
		{"placeholder-value", "", "k", "real-secret-value", false},
		{"placeholder-value", "", "k", "", false},

		// large-value
		{"large-value", "", "k", strings.Repeat("a", 10001), true},
		{"large-value", "", "k", strings.Repeat("a", 10000), false},
		{"large-value", "", "k", "short", false},

		// json-blob
		{"json-blob", "", "k", `{"key": "val"}`, true},
		{"json-blob", "", "k", `[1,2,3]`, true},
		{"json-blob", "", "k", `  {"key": "val"}  `, true},
		{"json-blob", "", "k", "not json", false},
		{"json-blob", "", "k", "{incomplete", false},
		{"json-blob", "", "k", "", false},

		// base64-config
		{"base64-config", "", "config_base64", "abc", true},
		{"base64-config", "", "base64_config", "abc", true},
		{"base64-config", "", "BASE64_CONFIG", "abc", true},
		{"base64-config", "", "password", "abc", false},
		{"base64-config", "", "config", "abc", false},

		// config-like-key compound keys (tokenized)
		{"config-like-key", "app/db", "db_host", "secret", true},
		{"config-like-key", "app/db", "api_url", "val", true},
		{"config-like-key", "app/db", "DB_PORT", "val", true},
		{"config-like-key", "app/db", "service.endpoint", "val", true},
		{"config-like-key", "app/db", "primary-region", "val", true},
		{"config-like-key", "app/db", "log_level", "val", true},
		{"config-like-key", "app/db", "max_connections", "val", true},
		{"config-like-key", "app/db", "secret_key", "val", false},
		{"config-like-key", "app/db", "private_key", "val", false},

		// feature-flag-key
		{"feature-flag-key", "", "enable_cache", "true", true},
		{"feature-flag-key", "", "disable_tls", "false", true},
		{"feature-flag-key", "", "feature_x", "on", true},
		{"feature-flag-key", "", "ff_new_ui", "on", true},
		{"feature-flag-key", "", "cache_enabled", "true", true},
		{"feature-flag-key", "", "tls_disabled", "false", true},
		{"feature-flag-key", "", "ENABLE_CACHE", "true", true},
		{"feature-flag-key", "", "password", "secret", false},
		{"feature-flag-key", "", "enablement", "x", false},

		// ip-address-value
		{"ip-address-value", "", "k", "10.0.0.1", true},
		{"ip-address-value", "", "k", "192.168.1.1:8080", true},
		{"ip-address-value", "", "k", " 127.0.0.1 ", true},
		{"ip-address-value", "", "k", "5432", false},
		{"ip-address-value", "", "k", "not.an.ip.addr", false},
		{"ip-address-value", "", "k", "", false},

		// url-value
		{"url-value", "", "k", "https://api.example.com/v1", true},
		{"url-value", "", "k", "http://localhost:8200", true},
		{"url-value", "", "k", "ftp://files.example.com", true},
		{"url-value", "", "k", "example.com", false},
		{"url-value", "", "k", "s3cr3t", false},
		{"url-value", "", "k", "", false},

		// file-path-value
		{"file-path-value", "", "k", "/etc/passwd", true},
		{"file-path-value", "", "k", "./config.yaml", true},
		{"file-path-value", "", "k", "../secrets", true},
		{"file-path-value", "", "k", `C:\Users\app`, true},
		{"file-path-value", "", "k", "/", false},
		{"file-path-value", "", "k", "plainvalue", false},
		{"file-path-value", "", "k", "https://x.com/y", false},
		{"file-path-value", "", "k", "", false},

		// email-value
		{"email-value", "", "k", "admin@example.com", true},
		{"email-value", "", "k", "first.last@sub.example.co", true},
		{"email-value", "", "k", "not-an-email", false},
		{"email-value", "", "k", "a@b", false},
		{"email-value", "", "k", "", false},

		// Unicode edge cases
		{"config-like-key", "", "host", "日本語", true},
		{"placeholder-value", "", "k", "CHANGEME 日本", true},
	}

	ruleMap := make(map[string]Rule)
	for _, r := range rules {
		ruleMap[r.Name] = r
	}

	for _, tt := range tests {
		t.Run(tt.rule+"/"+tt.key+"/"+truncForName(tt.value), func(t *testing.T) {
			r, ok := ruleMap[tt.rule]
			if !ok {
				t.Fatalf("rule %q not found", tt.rule)
			}
			got := r.Check(tt.path, tt.key, tt.value)
			if got != tt.expected {
				t.Errorf("Check(%q, %q, %q) = %v, want %v", tt.path, tt.key, truncForName(tt.value), got, tt.expected)
			}
		})
	}
}

func truncForName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}
