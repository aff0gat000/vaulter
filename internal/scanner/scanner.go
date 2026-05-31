package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aff0gat000/vaulter/internal/rules"
	"github.com/aff0gat000/vaulter/internal/vault"
)

// MaxPatternLength is the maximum allowed regex pattern length to prevent ReDoS.
const MaxPatternLength = 1024

// MaxTruncate is the maximum truncation length to cap memory usage.
const MaxTruncate = 10000

// Match represents a search hit.
type Match struct {
	Path  string `json:"path"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ScanResult holds both search matches and audit findings.
type ScanResult struct {
	Matches  []Match
	Findings []rules.Finding
}

// Options controls what the scanner looks for.
type Options struct {
	KeyPattern   string       // regex to match against keys
	ValuePattern string       // regex to match against values
	Audit        bool         // run the default audit rules
	Rules        []rules.Rule // explicit audit rules; overrides Audit when set
	ShowValues   bool         // show actual values (false = mask)
}

// Scanner processes vault secrets.
type Scanner struct {
	opts    Options
	keyRe   *regexp.Regexp
	valueRe *regexp.Regexp
	rules   []rules.Rule
}

// New creates a Scanner from the given options.
func New(opts Options) (*Scanner, error) {
	s := &Scanner{opts: opts}

	if opts.KeyPattern != "" {
		if len(opts.KeyPattern) > MaxPatternLength {
			return nil, fmt.Errorf("key pattern too long (%d chars, max %d)", len(opts.KeyPattern), MaxPatternLength)
		}
		re, err := regexp.Compile(opts.KeyPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid key pattern: %w", err)
		}
		s.keyRe = re
	}
	if opts.ValuePattern != "" {
		if len(opts.ValuePattern) > MaxPatternLength {
			return nil, fmt.Errorf("value pattern too long (%d chars, max %d)", len(opts.ValuePattern), MaxPatternLength)
		}
		re, err := regexp.Compile(opts.ValuePattern)
		if err != nil {
			return nil, fmt.Errorf("invalid value pattern: %w", err)
		}
		s.valueRe = re
	}
	switch {
	case opts.Rules != nil:
		s.rules = opts.Rules
	case opts.Audit:
		s.rules = rules.DefaultRules()
	}
	return s, nil
}

// Process checks a single secret against search patterns and audit rules.
func (s *Scanner) Process(secret vault.Secret) ScanResult {
	var result ScanResult

	for k, v := range secret.Data {
		val := fmt.Sprintf("%v", v)

		displayVal := s.displayValue(val)

		// Search matching
		if s.keyRe != nil && s.keyRe.MatchString(k) {
			result.Matches = append(result.Matches, Match{Path: secret.Path, Key: k, Value: truncate(displayVal, 120)})
		} else if s.valueRe != nil && s.valueRe.MatchString(val) {
			result.Matches = append(result.Matches, Match{Path: secret.Path, Key: k, Value: truncate(displayVal, 120)})
		}

		// Audit rules
		for _, rule := range s.rules {
			if rule.Check(secret.Path, k, val) {
				result.Findings = append(result.Findings, rules.Finding{
					Path:     secret.Path,
					Key:      k,
					Value:    truncate(displayVal, 80),
					Rule:     rule.Name,
					Severity: rule.Severity,
				})
			}
		}
	}

	return result
}

func (s *Scanner) displayValue(val string) string {
	if s.opts.ShowValues {
		return val
	}
	return "********"
}

func truncate(s string, max int) string {
	if max > MaxTruncate {
		max = MaxTruncate
	}
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
