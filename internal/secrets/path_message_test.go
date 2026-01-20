package secrets

import (
	"context"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestMessageSigningAndVerification(t *testing.T) {
	backend, storage := getTestBackend(t)

	msg := "test message"

	var offchainSignature, rawSignature solana.Signature

	backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "wallet/test",
		Storage:   storage,
	})

	t.Run("Sign with Offchain Preamble", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "wallet/test/message/sign",
			Storage:   storage,
			Data: map[string]any{
				"message": msg,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp.Data["signature"])

		offchainSignature, err = solana.SignatureFromBase58(resp.Data["signature"].(string))
		assert.NoError(t, err)
		assert.False(t, offchainSignature.IsZero())
	})

	t.Run("Verify Offchain Preamble", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "wallet/test/message/verify",
			Storage:   storage,
			Data: map[string]any{
				"message":   msg,
				"signature": offchainSignature.String(),
			},
		})

		assert.NoError(t, err)
		assert.True(t, resp.Data["verified"].(bool))
	})

	t.Run("Sign Raw", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "wallet/test/message/sign",
			Storage:   storage,
			Data: map[string]any{
				"offchain": false,
				"message":  msg,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp.Data["signature"])

		rawSignature, err = solana.SignatureFromBase58(resp.Data["signature"].(string))
		assert.NoError(t, err)
		assert.False(t, rawSignature.IsZero())
	})

	t.Run("Verify Raw", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "wallet/test/message/verify",
			Storage:   storage,
			Data: map[string]any{
				"message":   msg,
				"offchain":  false,
				"signature": rawSignature.String(),
			},
		})

		assert.NoError(t, err)
		assert.True(t, resp.Data["verified"].(bool))
	})

}
