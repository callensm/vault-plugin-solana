package secrets

import (
	"context"
	"encoding/base64"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathMessage(s *SolanaSecretsBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallet/" + framework.GenericNameRegex("id") + "/message/sign",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier of the wallet keypair",
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
			Pattern: "wallet/" + framework.GenericNameRegex("id") + "/message/verify",
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeString,
					Description: "Unique identifier for the wallet keypair",
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
	}
}

func (s *SolanaSecretsBackend) pathWalletSignMessage(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (s *SolanaSecretsBackend) pathWalletVerifyMessageSignature(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
