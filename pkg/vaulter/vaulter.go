// SPDX-License-Identifier: Apache-2.0

// Package vaulter provides a programmatic API for searching and auditing
// HashiCorp Vault KV secrets, mirroring the behavior of the vaulter CLI.
//
// It walks a KV mount recursively and lets callers either search for keys and
// values matching a regular expression, or audit secrets against a set of
// rules that flag non-secret / config-like data that probably should not live
// in Vault.
//
// Connection details default to the standard VAULT_ADDR and VAULT_TOKEN
// environment variables, but can be supplied explicitly via Config.
//
//	c, err := vaulter.New(vaulter.Config{Mount: "secret"})
//	if err != nil { ... }
//	findings, scanned, err := c.Audit(ctx, "apps/")
package vaulter

import (
	"context"
	"time"

	"github.com/aff0gat000/vaulter/internal/rules"
	"github.com/aff0gat000/vaulter/internal/scanner"
	"github.com/aff0gat000/vaulter/internal/vault"
)

// Match is a single search hit (path, key, and possibly masked value).
type Match = scanner.Match

// Finding is a single audit issue flagged against a secret.
type Finding = rules.Finding

// Rule is an audit rule used by Audit. Callers may supply custom rules or use
// DefaultRules.
type Rule = rules.Rule

// DefaultRules returns the built-in audit rules for detecting non-secret /
// config-like data.
func DefaultRules() []Rule { return rules.DefaultRules() }

// Config controls how the client connects to Vault and which KV engine it
// reads. Address and Token fall back to VAULT_ADDR / VAULT_TOKEN when empty.
type Config struct {
	Address   string        // overrides VAULT_ADDR when set
	Token     string        // overrides VAULT_TOKEN when set
	Mount     string        // KV mount path; defaults to "secret"
	KVVersion int           // KV engine version, 1 or 2; defaults to 2
	Insecure  bool          // skip TLS verification (not recommended)
	Timeout   time.Duration // per-request timeout; defaults to 30s
}

// SearchOptions controls a Search call. At least one of KeyPattern or
// ValuePattern must be set.
type SearchOptions struct {
	KeyPattern   string // regex matched against secret keys
	ValuePattern string // regex matched against secret values
	ShowValues   bool   // include actual values (false masks them)
}

// Client is a reusable handle to a Vault KV engine.
type Client struct {
	vc      *vault.Client
	timeout time.Duration
}

// New creates a Client from cfg, applying sensible defaults.
func New(cfg Config) (*Client, error) {
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}
	kvVer := cfg.KVVersion
	if kvVer == 0 {
		kvVer = 2
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	if err := vault.ValidateMountAndPrefix(mount, ""); err != nil {
		return nil, err
	}

	vc, err := vault.NewClient(vault.ClientConfig{
		Address:  cfg.Address,
		Token:    cfg.Token,
		Mount:    mount,
		KVVer:    kvVer,
		Insecure: cfg.Insecure,
		Timeout:  timeout,
	})
	if err != nil {
		return nil, err
	}

	return &Client{vc: vc, timeout: timeout}, nil
}

// SkippedPaths returns the paths the most recent Search or Audit could not read
// because the token lacked permission (HTTP 403). Such paths are skipped rather
// than failing the whole walk, so a token with partial access still audits
// everything it can reach. Valid to read after Search or Audit returns.
func (c *Client) SkippedPaths() []string { return c.vc.SkippedPaths() }

// Search walks the KV engine under prefix and returns matches for the given
// patterns along with the number of secrets scanned.
func (c *Client) Search(ctx context.Context, prefix string, opts SearchOptions) ([]Match, int, error) {
	sc, err := scanner.New(scanner.Options{
		KeyPattern:   opts.KeyPattern,
		ValuePattern: opts.ValuePattern,
		ShowValues:   opts.ShowValues,
	})
	if err != nil {
		return nil, 0, err
	}

	matches, _, count, err := c.scan(ctx, prefix, sc)
	return matches, count, err
}

// AuditOptions controls an Audit call.
type AuditOptions struct {
	Rules      []Rule // custom rules; DefaultRules() is used when nil
	ShowValues bool   // include actual values in findings (false masks them)
}

// Audit walks the KV engine under prefix and returns findings produced by the
// configured rules (DefaultRules when none are supplied) along with the number
// of secrets scanned. Values are masked unless opts.ShowValues is set.
func (c *Client) Audit(ctx context.Context, prefix string, opts AuditOptions) ([]Finding, int, error) {
	auditRules := opts.Rules
	if len(auditRules) == 0 {
		auditRules = rules.DefaultRules()
	}
	sc, err := scanner.New(scanner.Options{Rules: auditRules, ShowValues: opts.ShowValues})
	if err != nil {
		return nil, 0, err
	}

	_, findings, count, err := c.scan(ctx, prefix, sc)
	return findings, count, err
}

// scan runs the walk-and-process pipeline shared by Search and Audit.
func (c *Client) scan(ctx context.Context, prefix string, sc *scanner.Scanner) ([]Match, []Finding, int, error) {
	if err := vault.ValidateMountAndPrefix("", prefix); err != nil {
		return nil, nil, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	secrets := make(chan vault.Secret, 50)
	errCh := make(chan error, 1)
	go func() { errCh <- c.vc.Walk(ctx, prefix, secrets) }()

	var matches []Match
	var findings []Finding
	count := 0
	for secret := range secrets {
		count++
		res := sc.Process(secret)
		matches = append(matches, res.Matches...)
		findings = append(findings, res.Findings...)
	}

	if err := <-errCh; err != nil {
		return nil, nil, count, err
	}
	return matches, findings, count, nil
}
