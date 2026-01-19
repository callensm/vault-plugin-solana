package secrets

import (
	"context"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/callensm/vault-plugin-solana/internal/message"
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
					Description: "The message to be signed by the wallet",
					Required:    true,
				},
				"offchain": {
					Type:        framework.TypeBool,
					Description: "Whether to sign the message with the Solana offchain header",
					Default:     true,
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
					Description: "The message that was signed by the wallet",
					Required:    true,
				},
				"offchain": {
					Type:        framework.TypeBool,
					Description: "Whether to verify the message with the Solana offchain header",
					Default:     true,
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

	msg := data.Get("message").(string)
	if msg == "" {
		return logical.ErrorResponse("empty or missing message to be signed"), nil
	}

	offchain := data.Get("offchain").(bool)

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

	signingMessage := []byte(msg)
	if offchain {
		signingMessage = message.CreateOffchainMessageWithPreamble(&message.OffchainMessageOpts{
			MessageBody: signingMessage,
			Version:     0,
		})
	}

	sig, err := wallet.PrivateKey.Sign(signingMessage)
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

	msg := data.Get("message").(string)
	if msg == "" {
		return logical.ErrorResponse("empty or missing message to be signed"), nil
	}

	offchain := data.Get("offchain").(bool)

	signature := data.Get("signature").(string)
	if signature == "" {
		return logical.ErrorResponse("empty or missing signature"), nil
	}

	sig, err := solana.SignatureFromBase58(signature)
	if err != nil {
		return logical.ErrorResponse("invalid signature"), nil
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

	verificationMessage := []byte(msg)
	if offchain {
		verificationMessage = message.CreateOffchainMessageWithPreamble(&message.OffchainMessageOpts{
			MessageBody: verificationMessage,
			Version:     0,
		})
	}

	ok := wallet.PublicKey().Verify(verificationMessage, sig)

	return &logical.Response{
		Data: map[string]any{
			"verified": ok,
		},
	}, nil
}
