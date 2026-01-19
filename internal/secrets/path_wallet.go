package secrets

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathWallet(s *SolanaSecretsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallet/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier for the wallet keypair",
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "Base-58 encoded private key to be imported instead of generating a new random keypair",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: s.pathWalletWrite,
					Summary:  "Generate a new wallet keypair",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: s.pathWalletRead,
					Summary:  "Read a wallet keypair",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: s.pathWalletDelete,
					Summary:  "Delete a wallet keypair",
				},
			},
			ExistenceCheck: s.pathWalletExistenceCheck,
		},
		{
			Pattern: "wallet/" + framework.GenericNameRegex("id") + "/pubkey",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier for the wallet keypair",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: s.pathWalletPublicRead,
					Summary:  "Read the public key of a wallet keypair",
				},
			},
		},
		{
			Pattern: "wallets/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: s.pathWalletList,
					Summary:  "List all wallet keypair identifiers that are stored",
				},
			},
		},
	}
}

func (s *SolanaSecretsBackend) pathWalletDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	if err := req.Storage.Delete(ctx, "wallet/"+id); err != nil {
		return nil, err
	}

	return nil, nil
}

func (s *SolanaSecretsBackend) pathWalletExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	id := data.Get("id").(string)
	entry, err := s.getWallet(ctx, req.Storage, id)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (s *SolanaSecretsBackend) pathWalletRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	entry, err := s.getWallet(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"private_key": entry.PrivateKey,
			"public_key":  entry.PublicKey,
		},
	}, nil
}

func (s *SolanaSecretsBackend) pathWalletList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "wallet/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (s *SolanaSecretsBackend) pathWalletPublicRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	entry, err := s.getWallet(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]any{
			"public_key": entry.PublicKey,
		},
	}, nil
}

func (s *SolanaSecretsBackend) pathWalletWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	privateKey, ok := data.GetOk("private_key")

	exists, err := s.pathWalletExistenceCheck(ctx, req, data)
	if err != nil {
		return nil, err
	}

	if exists {
		return logical.ErrorResponse("wallet already exists"), nil
	}

	var priv solana.PrivateKey

	if ok && privateKey != "" {
		priv, err = solana.PrivateKeyFromBase58(privateKey.(string))
		if err != nil {
			return logical.ErrorResponse("invalid private key"), nil
		}
	} else {
		priv, err = solana.NewRandomPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
	}

	entry := &WalletEntry{
		PrivateKey: priv.String(),
		PublicKey:  priv.PublicKey().String(),
	}

	if err := s.setWallet(ctx, req.Storage, id, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"public_key": entry.PublicKey,
		},
	}, nil
}
