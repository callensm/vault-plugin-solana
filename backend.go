package solana

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/callensm/vault-plugin-solana/internal/auth"
	"github.com/callensm/vault-plugin-solana/internal/secrets"
)

func AuthFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return auth.Factory(ctx, conf)
}

func SecretsFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return secrets.Factory(ctx, conf)
}
