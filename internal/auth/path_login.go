package auth

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathLogin(s *SolanaAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"nonce": {
				Type:        framework.TypeString,
				Description: "The generated nonce that was signed",
				Required:    true,
			},
			"public_key": {
				Type:        framework.TypeString,
				Description: "The public key of the wallet to authenticate",
				Required:    true,
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The nonce message signature to be verified",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: s.pathLoginUpdate,
				Summary:  "Login with signature verification",
			},
		},
	}
}

func (s *SolanaAuthBackend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	nonce, ok := data.Get("nonce").(string)
	if !ok || nonce == "" {
		return logical.ErrorResponse("missing or empty nonce"), nil
	}

	pubkey, ok := data.Get("public_key").(string)
	if !ok || pubkey == "" {
		return logical.ErrorResponse("missing or empty public key"), nil
	}

	signature, ok := data.Get("signature").(string)
	if !ok || signature == "" {
		return logical.ErrorResponse("missing or empty signature"), nil
	}

	storageKey := fmt.Sprintf(nonceStorageFormat, pubkey)
	entry, err := req.Storage.Get(ctx, storageKey)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("nonce not found"), nil
	}

	var storedNonce NonceEntry
	if err := entry.DecodeJSON(&storedNonce); err != nil {
		return nil, err
	}

	if time.Now().Unix() > storedNonce.ExpiresAt {
		req.Storage.Delete(ctx, storageKey)
		return logical.ErrorResponse("nonce expired"), nil
	}

	if storedNonce.Nonce != nonce {
		return logical.ErrorResponse("nonce mismatch"), nil
	}

	if storedNonce.PublicKey != pubkey {
		return logical.ErrorResponse("public key mismatch"), nil
	}

	if !ed25519.Verify(ed25519.PublicKey(pubkey), []byte(nonce), []byte(signature)) {
		return logical.ErrorResponse("signature verification failed"), nil
	}

	req.Storage.Delete(ctx, storageKey)

	config, err := s.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]any{
				"public_key": pubkey,
			},
			Policies: config.TokenPolicies,
			Metadata: map[string]string{
				"public_key": pubkey,
			},
			DisplayName: fmt.Sprintf("solana-%s", pubkey[:8]),
			LeaseOptions: logical.LeaseOptions{
				TTL:       time.Duration(config.TokenTtl) * time.Second,
				MaxTTL:    time.Duration(config.TokenMaxTtl) * time.Second,
				Renewable: true,
			},
		},
	}, nil
}
