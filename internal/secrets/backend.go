package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/callensm/vault-plugin-solana/version"
)

const (
	backendHelp = `
The Solana secrets backend allows for the dynamic and secure
creation, access, and management of wallet keypair material.
`
)

type WalletEntry struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type SolanaSecretsBackend struct {
	*framework.Backend
}

func newSolanaSecretsBackend() *SolanaSecretsBackend {
	var s = SolanaSecretsBackend{}
	s.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"wallet/",
			},
		},
		Paths: framework.PathAppend(
			pathMessage(&s),
			pathWallet(&s),
		),
		Secrets:        []*framework.Secret{},
		BackendType:    logical.TypeLogical,
		RunningVersion: fmt.Sprintf("v%s", version.Version),
	}
	return &s
}

func (s *SolanaSecretsBackend) getWallet(ctx context.Context, store logical.Storage, id string) (*WalletEntry, error) {
	entry, err := store.Get(ctx, "wallet/"+id)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var wallet WalletEntry
	if err := entry.DecodeJSON(&wallet); err != nil {
		return nil, err
	}

	return &wallet, nil
}

func (s *SolanaSecretsBackend) setWallet(ctx context.Context, store logical.Storage, id string, w *WalletEntry) error {
	entry, err := logical.StorageEntryJSON("wallet/"+id, w)
	if err != nil {
		return err
	}

	return store.Put(ctx, entry)
}
