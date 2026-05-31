package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/yb/vaulter/pkg/vaulter"
)

// Version is set at build time via ldflags.
var Version = "dev"

// Config holds all CLI flag values.
type Config struct {
	Mount      string
	KVVersion  int
	Prefix     string
	KeyPattern string
	ValPattern string
	Audit      bool
	JSON       bool
	Insecure   bool
	Timeout    time.Duration
	ShowValues bool
}

func NewRootCmd() *cobra.Command {
	cfg := &Config{}

	root := &cobra.Command{
		Use:     "vaulter",
		Short:   "Search and audit HashiCorp Vault secrets",
		Version: Version,
		Long: `Vaulter recursively walks a Vault KV secrets engine and lets you:
  - Search for keys or values matching a regex pattern
  - Audit secrets for config-like data, placeholders, and other non-secret items

Useful for vault maintenance, migration planning, and policy enforcement.

Requires VAULT_ADDR and VAULT_TOKEN environment variables.`,
	}

	root.PersistentFlags().StringVarP(&cfg.Mount, "mount", "m", "secret", "KV engine mount path")
	root.PersistentFlags().IntVar(&cfg.KVVersion, "kv-version", 2, "KV engine version (1 or 2)")
	root.PersistentFlags().StringVarP(&cfg.Prefix, "prefix", "p", "", "Path prefix to search under")
	root.PersistentFlags().BoolVar(&cfg.JSON, "json", false, "Output as JSON")
	root.PersistentFlags().BoolVar(&cfg.Insecure, "insecure", false, "Skip TLS verification (not recommended)")
	root.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "Vault request timeout")
	root.PersistentFlags().BoolVar(&cfg.ShowValues, "show-values", false, "Show secret values (masked by default)")

	root.AddCommand(newSearchCmd(cfg))
	root.AddCommand(newAuditCmd(cfg))

	return root
}

func newSearchCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search secrets by key or value pattern",
		Example: `  vaulter search --key "password|token"
  vaulter search --value "prod\.example\.com"
  vaulter search --key "DB_" --mount secret --prefix apps/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.KeyPattern == "" && cfg.ValPattern == "" {
				return fmt.Errorf("at least one of --key or --value is required")
			}
			return runSearch(cfg)
		},
	}
	cmd.Flags().StringVarP(&cfg.KeyPattern, "key", "k", "", "Regex pattern to match against secret keys")
	cmd.Flags().StringVarP(&cfg.ValPattern, "value", "v", "", "Regex pattern to match against secret values")
	return cmd
}

func newAuditCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Find non-secret and config-like data in vault",
		Long: `Scans secrets for items that probably shouldn't be stored in Vault:
  - Config-like keys (host, port, region, timeout, etc.)
  - Boolean and numeric-only values
  - Empty or placeholder values
  - Large values and JSON blobs
  - Base64-encoded configs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(cfg)
		},
	}
}

func newClient(cfg *Config) (*vaulter.Client, error) {
	if os.Getenv("VAULT_ADDR") == "" {
		return nil, fmt.Errorf("VAULT_ADDR environment variable is not set")
	}
	return vaulter.New(vaulter.Config{
		Mount:     cfg.Mount,
		KVVersion: cfg.KVVersion,
		Insecure:  cfg.Insecure,
		Timeout:   cfg.Timeout,
	})
}

func runSearch(cfg *Config) error {
	client, err := newClient(cfg)
	if err != nil {
		return err
	}
	matches, count, err := client.Search(context.Background(), cfg.Prefix, vaulter.SearchOptions{
		KeyPattern:   cfg.KeyPattern,
		ValuePattern: cfg.ValPattern,
		ShowValues:   cfg.ShowValues,
	})
	if err != nil {
		return err
	}
	return report(cfg, matches, nil, count)
}

func runAudit(cfg *Config) error {
	client, err := newClient(cfg)
	if err != nil {
		return err
	}
	findings, count, err := client.Audit(context.Background(), cfg.Prefix)
	if err != nil {
		return err
	}
	return report(cfg, nil, findings, count)
}

func report(cfg *Config, matches []vaulter.Match, findings []vaulter.Finding, secretCount int) error {
	if cfg.JSON {
		return outputJSON(matches, findings, secretCount)
	}

	if len(matches) > 0 {
		printMatches(matches)
	}
	if len(findings) > 0 {
		printFindings(findings)
	}

	fmt.Fprintf(os.Stderr, "\nScanned %d secrets", secretCount)
	if len(matches) > 0 {
		fmt.Fprintf(os.Stderr, ", %d matches", len(matches))
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, ", %d findings", len(findings))
	}
	fmt.Fprintln(os.Stderr)

	if len(matches) == 0 && len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "No results found.")
	}

	return nil
}

func printMatches(matches []vaulter.Match) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PATH\tKEY\tVALUE")
	for _, m := range matches {
		fmt.Fprintf(w, "%s\t%s\t%s\n", m.Path, m.Key, m.Value)
	}
	w.Flush()
}

func printFindings(findings []vaulter.Finding) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tRULE\tPATH\tKEY\tVALUE")
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Rule, f.Path, f.Key, f.Value)
	}
	w.Flush()
}

func outputJSON(matches []vaulter.Match, findings []vaulter.Finding, count int) error {
	out := map[string]interface{}{
		"secrets_scanned": count,
		"matches":         matches,
		"findings":        findings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
