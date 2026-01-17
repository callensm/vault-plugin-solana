package backend

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathWallet(s *SolanaBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallet/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier for the wallet keypair",
					Required:    true,
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
			Pattern: "wallet/" + framework.GenericNameRegex("id") + "/public",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier of the wallet keypair",
					Required:    true,
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
			Pattern: "wallet/" + framework.GenericNameRegex("id") + "/sign-message",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier of the wallet keypair",
					Required:    true,
				},
				"message": {
					Type:        framework.TypeString,
					Description: "The base-64 encoded message to be signed by the wallet",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: s.pathWalletSignMessage,
					Summary:  "Sign a message with the wallet's private key",
				},
			},
		},
		{
			Pattern: "wallet/" + framework.GenericNameRegex("id") + "/verify-message",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier of the wallet keypair",
					Required:    true,
				},
				"message": {
					Type:        framework.TypeString,
					Description: "The base-64 encoded message to be signed by the wallet",
					Required:    true,
				},
				"signature": {
					Type:        framework.TypeString,
					Description: "The base-58 signature of the message being verified",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: s.pathWalletVerifyMessageSignature,
					Summary:  "Verify that the wallet keypair signed a message",
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

func (s *SolanaBackend) pathWalletDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	if err := req.Storage.Delete(ctx, "wallet/"+id); err != nil {
		return nil, err
	}

	return nil, nil
}

func (s *SolanaBackend) pathWalletExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	id := data.Get("id").(string)
	entry, err := s.getWallet(ctx, req.Storage, id)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (s *SolanaBackend) pathWalletRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (s *SolanaBackend) pathWalletList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "wallet/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (s *SolanaBackend) pathWalletPublicRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (s *SolanaBackend) pathWalletSignMessage(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	messageB64 := data.Get("message").(string)
	if messageB64 == "" {
		return logical.ErrorResponse("empty or missing message to be signed"), nil
	}

	msg, err := base64.StdEncoding.DecodeString(messageB64)
	if err != nil {
		return logical.ErrorResponse("invalid base64 message: %v", err), nil
	}

	entry, err := s.getWallet(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("wallet not found"), nil
	}

	wallet, err := solana.WalletFromPrivateKeyBase58(entry.PrivateKey)
	if err != nil {
		return logical.ErrorResponse("invalid wallet private key: %v", err), nil
	}

	sig, err := wallet.PrivateKey.Sign([]byte(msg))
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"signature": sig.String(),
		},
	}, nil
}

func (s *SolanaBackend) pathWalletVerifyMessageSignature(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	messageB64 := data.Get("message").(string)
	if messageB64 == "" {
		return logical.ErrorResponse("empty or missing message to be signed"), nil
	}

	signature := data.Get("signature").(string)
	if signature == "" {
		return logical.ErrorResponse("empty or missing signature"), nil
	}

	sig, err := solana.SignatureFromBase58(signature)
	if err != nil {
		return logical.ErrorResponse("invalid signature"), nil
	}

	msg, err := base64.StdEncoding.DecodeString(messageB64)
	if err != nil {
		return logical.ErrorResponse("invalid base64 message: %v", err), nil
	}

	entry, err := s.getWallet(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("wallet not found"), nil
	}

	wallet, err := solana.WalletFromPrivateKeyBase58(entry.PrivateKey)
	if err != nil {
		return logical.ErrorResponse("invalid wallet private key: %v", err), nil
	}

	ok := wallet.PublicKey().Verify(msg, sig)

	return &logical.Response{
		Data: map[string]any{
			"ok": ok,
		},
	}, nil
}

func (s *SolanaBackend) pathWalletWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	if id == "" {
		return logical.ErrorResponse("missing wallet id"), nil
	}

	exists, err := s.pathWalletExistenceCheck(ctx, req, data)
	if err != nil {
		return nil, err
	}

	if exists {
		return logical.ErrorResponse("wallet already exists"), nil
	}

	priv, err := solana.NewRandomPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
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
			"message":    "Wallet created successfully. Private key is securely stored.",
		},
	}, nil
}
