package auth

import (
	"context"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"

	"github.com/callensm/vault-plugin-solana/internal/message"
)

func TestOffchainMessageSigningAuthentication(t *testing.T) {
	backend, storage := getTestBackend(t)

	wallet := solana.NewWallet()

	var nonce string
	var signature solana.Signature
	var err error

	t.Run("Generate Message Nonce", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "nonce",
			Storage:   storage,
			Data: map[string]any{
				"public_key": wallet.PublicKey().String(),
			},
		})

		assert.NoError(t, err)
		assert.Contains(t, resp.Data, "nonce")

		nonce = resp.Data["nonce"].(string)
	})

	t.Run("Sign Offchain Message", func(t *testing.T) {
		t.Helper()

		msg := message.CreateOffchainMessageWithPreamble(&message.OffchainMessageOpts{
			MessageBody: []byte(nonce),
			Version:     0,
		})

		signature, err = wallet.PrivateKey.Sign(msg)
		assert.NoError(t, err)
	})

	t.Run("Login with Offchain Message Signature", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "login",
			Storage:   storage,
			Data: map[string]any{
				"public_key": wallet.PublicKey().String(),
				"signature":  signature.String(),
			},
		})

		assert.NoError(t, err)
		assert.Equal(t, resp.Auth.InternalData["public_key"].(string), wallet.PublicKey().String())
		assert.NotNil(t, resp.Auth)
	})
}
