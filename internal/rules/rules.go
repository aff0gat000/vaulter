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
	// Filesystem path: unix absolute (/x), relative (./ ../), or Windows drive (C:\).
	filePathRe = regexp.MustCompile(`^(/[^/\s]|\./|\.\./|[A-Za-z]:\\)`)
	// Email address.
	emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
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
				return urlRe.MatchString(strings.TrimSpace(value))
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
