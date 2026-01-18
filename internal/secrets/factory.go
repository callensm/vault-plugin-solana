package secrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newSolanaSecretsBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
