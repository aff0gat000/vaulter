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

// Precompiled patterns shared across rule checks.
var (
	numericOnlyRe = regexp.MustCompile(`^\d+$`)
	// IPv4 address, optionally with a :port suffix.
	ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(:\d+)?$`)
	// http(s)/ftp URL.
	urlRe = regexp.MustCompile(`^(https?|ftp)://[^\s]+$`)
	// A URL whose authority embeds credentials (userinfo@host) — such values
	// carry secrets and must NOT be treated as non-secret config.
	credentialURLRe = regexp.MustCompile(`^(https?|ftp)://[^/\s]*@`)
	// Filesystem path: unix absolute (/x), relative (./ ../), or Windows drive (C:\).
	filePathRe = regexp.MustCompile(`^(/[^/\s]|\./|\.\./|[A-Za-z]:\\)`)
	// Email address. Deliberately strict (RFC-ish local/domain charset) so it
	// does not match credential-bearing URLs like "https://u:p@host/path".
	emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	// keyTokenSplit splits a key into tokens on _, -, ., and space.
	keyTokenSplit = regexp.MustCompile(`[._\- ]+`)
)

// configExactKeys are full key names that strongly indicate config data.
var configExactKeys = map[string]bool{
	"log_level": true, "loglevel": true, "app_name": true, "service_name": true,
	"max_connections": true, "max_retries": true,
}

// configTokens are individual key tokens that indicate config data
// (matched against any token in the key, so "db_host" matches via "host").
var configTokens = map[string]bool{
	"host": true, "hostname": true, "port": true, "endpoint": true,
	"url": true, "uri": true, "region": true, "environment": true,
	"env": true, "namespace": true, "debug": true, "verbose": true,
	"timeout": true, "retry": true, "retries": true, "version": true,
	"scheme": true, "protocol": true, "cluster": true, "zone": true,
	"datacenter": true, "interval": true, "ttl": true, "threshold": true,
	"replicas": true,
}

// placeholderWholeValues are values that, taken in their entirety, indicate a
// placeholder/unset secret. Matched after trimming and lower-casing so they do
// NOT fire on legitimate values that merely contain the word (e.g. the value
// "example" is a placeholder, but "example.com" is not).
var placeholderWholeValues = map[string]bool{
	"changeme": true, "change_me": true, "change-me": true, "changethis": true,
	"todo": true, "tbd": true, "fixme": true, "placeholder": true,
	"example": true, "default": true, "none": true, "null": true,
	"n/a": true, "xxx": true, "xxxx": true,
}

// placeholderMarkers are unambiguous placeholder/templating fragments matched as
// substrings, because they essentially never appear inside real secret values.
// Domain/email forms such as "example.com" are intentionally excluded by
// requiring a separator (e.g. "example_") rather than a bare "example".
var placeholderMarkers = []string{
	"changeme", "change me", "change_me", "change-me", "change this",
	"replace_me", "replaceme", "replace with", "replace-with",
	"your_", "your-", "insert_", "insert-", "example_", "example-",
	"<change", "todo:", "fixme:", "${", "{{", "<%",
}

// DefaultRules returns built-in rules for detecting non-secret / config-like data.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:     "config-like-key",
			Severity: "warning",
			Check: func(_, key, _ string) bool {
				lower := strings.ToLower(strings.TrimSpace(key))
				if configExactKeys[lower] {
					return true
				}
				for _, tok := range keyTokenSplit.Split(lower, -1) {
					if configTokens[tok] {
						return true
					}
				}
				return false
			},
		},
		{
			Name:     "feature-flag-key",
			Severity: "warning",
			Check: func(_, key, _ string) bool {
				lower := strings.ToLower(strings.TrimSpace(key))
				for _, p := range []string{"enable_", "disable_", "feature_", "ff_"} {
					if strings.HasPrefix(lower, p) {
						return true
					}
				}
				return strings.HasSuffix(lower, "_enabled") || strings.HasSuffix(lower, "_disabled")
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
				return numericOnlyRe.MatchString(v)
			},
		},
		{
			Name:     "ip-address-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				return ipv4Re.MatchString(strings.TrimSpace(value))
			},
		},
		{
			Name:     "url-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				v := strings.TrimSpace(value)
				// A plain endpoint URL is config; a URL carrying credentials is
				// a secret, so don't flag it as non-secret data.
				return urlRe.MatchString(v) && !credentialURLRe.MatchString(v)
			},
		},
		{
			Name:     "file-path-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				return filePathRe.MatchString(strings.TrimSpace(value))
			},
		},
		{
			Name:     "email-value",
			Severity: "warning",
			Check: func(_, _, value string) bool {
				return emailRe.MatchString(strings.TrimSpace(value))
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
				if v == "" {
					return false
				}
				if placeholderWholeValues[v] {
					return true
				}
				for _, m := range placeholderMarkers {
					if strings.Contains(v, m) {
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
