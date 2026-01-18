package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	nonceFormat        = "vault:solana:%s"
	nonceStorageFormat = "nonce/%s"
)

func pathNonce(s *SolanaAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "nonce",
		Fields: map[string]*framework.FieldSchema{
			"public_key": {
				Type:        framework.TypeString,
				Description: "The public key of the wallet to authenticate",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: s.pathNonceUpdate,
				Summary:  "Generate a nonce for authentication",
			},
		},
	}
}

func (s *SolanaAuthBackend) pathNonceUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	pubkey, ok := data.Get("public_key").(string)
	if !ok || pubkey == "" {
		return logical.ErrorResponse("missing or empty public key"), nil
	}

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate nonce bytes: %v", err)
	}

	nonceStr := base64.StdEncoding.EncodeToString(nonceBytes)
	nonce := &NonceEntry{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Nonce:     fmt.Sprintf(nonceFormat, nonceStr),
		PublicKey: pubkey,
	}

	storageKey := fmt.Sprintf(nonceStorageFormat, pubkey)
	entry, err := logical.StorageEntryJSON(storageKey, nonce)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"nonce":      nonce.Nonce,
			"expires_at": nonce.ExpiresAt,
		},
	}, nil
}
