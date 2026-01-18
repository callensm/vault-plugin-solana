package auth

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStorageKey   = "config"
	defaultTokenTtl    = 3600
	defaultTokenMaxTtl = 86400
)

func pathConfig(s *SolanaAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of policies to attach to tokens",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default TTL for tokens issued",
				Default:     defaultTokenTtl,
			},
			"token_max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum TTL for tokens issued",
				Default:     defaultTokenMaxTtl,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: s.pathConfigWrite,
				Summary:  "Configure the Solana auth backend",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: s.pathConfigRead,
				Summary:  "Read the Solana auth backend configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: s.pathConfigWrite,
				Summary:  "Configure the Solana auth backend",
			},
		},
	}
}

func (s *SolanaAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := s.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"token_ttl":      config.TokenTtl,
			"token_max_ttl":  config.TokenMaxTtl,
			"token_policies": config.TokenPolicies,
		},
	}, nil
}

func (s *SolanaAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := &AuthConfigEntry{
		TokenTtl:      data.Get("token_ttl").(int),
		TokenMaxTtl:   data.Get("token_max_ttl").(int),
		TokenPolicies: data.Get("token_policies").([]string),
	}

	entry, err := logical.StorageEntryJSON(configStorageKey, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (s *SolanaAuthBackend) getConfig(ctx context.Context, store logical.Storage) (*AuthConfigEntry, error) {
	entry, err := store.Get(ctx, configStorageKey)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return &AuthConfigEntry{
			TokenTtl:    defaultTokenTtl,
			TokenMaxTtl: defaultTokenMaxTtl,
		}, nil
	}

	var config AuthConfigEntry
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
