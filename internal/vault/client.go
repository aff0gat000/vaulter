package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Secret represents a single secret entry with its path and key-value data.
type Secret struct {
	Path string
	Data map[string]interface{}
}

// Walker is the interface for recursively walking Vault secrets.
type Walker interface {
	Walk(ctx context.Context, prefix string, out chan<- Secret) error
}

// ClientConfig holds configuration for creating a Vault client.
type ClientConfig struct {
	// Address overrides VAULT_ADDR when non-empty.
	Address string
	// Token overrides VAULT_TOKEN when non-empty.
	Token    string
	Mount    string
	KVVer    int
	Insecure bool
	Timeout  time.Duration
}

// Client wraps the Vault API client for recursive secret traversal.
type Client struct {
	api   *vaultapi.Client
	mount string
	kvVer int
}

// ValidateMountAndPrefix checks mount and prefix for path traversal.
func ValidateMountAndPrefix(mount, prefix string) error {
	for _, val := range []struct {
		name, v string
	}{{"mount", mount}, {"prefix", prefix}} {
		if strings.Contains(val.v, "..") {
			return fmt.Errorf("%s must not contain '..': %q", val.name, val.v)
		}
		if strings.HasPrefix(val.v, "/") {
			return fmt.Errorf("%s must not be an absolute path: %q", val.name, val.v)
		}
	}
	return nil
}

// NewClient creates a Client from environment config (VAULT_ADDR, VAULT_TOKEN).
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.KVVer != 1 && cfg.KVVer != 2 {
		return nil, fmt.Errorf("kv-version must be 1 or 2, got %d", cfg.KVVer)
	}

	if err := ValidateMountAndPrefix(cfg.Mount, ""); err != nil {
		return nil, err
	}

	vcfg := vaultapi.DefaultConfig()

	if !cfg.Insecure {
		if vcfg.HttpClient == nil {
			vcfg.HttpClient = &http.Client{}
		}
		transport := vcfg.HttpClient.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		if t, ok := transport.(*http.Transport); ok {
			if t.TLSClientConfig == nil {
				t.TLSClientConfig = &tls.Config{}
			}
			t.TLSClientConfig.InsecureSkipVerify = false
			vcfg.HttpClient.Transport = t
		}
	}

	if cfg.Timeout > 0 {
		vcfg.Timeout = cfg.Timeout
	}

	api, err := vaultapi.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	if cfg.Address != "" {
		if err := api.SetAddress(cfg.Address); err != nil {
			return nil, fmt.Errorf("setting vault address: %w", err)
		}
	}
	if cfg.Token != "" {
		api.SetToken(cfg.Token)
	}

	return &Client{api: api, mount: cfg.Mount, kvVer: cfg.KVVer}, nil
}

// Walk recursively lists all secrets under the given prefix and sends them to the channel.
func (c *Client) Walk(ctx context.Context, prefix string, out chan<- Secret) error {
	defer close(out)
	if err := ValidateMountAndPrefix("", prefix); err != nil {
		return err
	}
	return c.walk(ctx, prefix, out)
}

func (c *Client) walk(ctx context.Context, prefix string, out chan<- Secret) error {
	listPath := c.listPath(prefix)
	resp, err := c.api.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return fmt.Errorf("listing %s: %w", listPath, err)
	}
	if resp == nil || resp.Data == nil {
		return nil
	}

	keys, ok := resp.Data["keys"].([]interface{})
	if !ok {
		return nil
	}

	for _, k := range keys {
		key := fmt.Sprintf("%v", k)
		fullPath := path.Join(prefix, key)

		if strings.HasSuffix(key, "/") {
			if err := c.walk(ctx, fullPath, out); err != nil {
				return err
			}
			continue
		}

		secret, err := c.readSecret(ctx, fullPath)
		if err != nil {
			return err
		}
		if secret != nil {
			select {
			case out <- *secret:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (c *Client) listPath(prefix string) string {
	if c.kvVer == 2 {
		return path.Join(c.mount, "metadata", prefix)
	}
	return path.Join(c.mount, prefix)
}

func (c *Client) readSecret(ctx context.Context, secretPath string) (*Secret, error) {
	var readPath string
	if c.kvVer == 2 {
		readPath = path.Join(c.mount, "data", secretPath)
	} else {
		readPath = path.Join(c.mount, secretPath)
	}

	resp, err := c.api.Logical().ReadWithContext(ctx, readPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", readPath, err)
	}
	if resp == nil || resp.Data == nil {
		return nil, nil
	}

	data := resp.Data
	if c.kvVer == 2 {
		if inner, ok := data["data"].(map[string]interface{}); ok {
			data = inner
		}
	}

	return &Secret{Path: secretPath, Data: data}, nil
}
