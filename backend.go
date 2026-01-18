package solana

import (
	"context"

	"github.com/callensm/vault-plugin-solana/internal/backend"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return backend.InternalFactory(ctx, conf)
}
