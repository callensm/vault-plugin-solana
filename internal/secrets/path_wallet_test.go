package secrets

import (
	"context"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestWalletCreation(t *testing.T) {
	backend, storage := getTestBackend(t)

	t.Run("Generate Random Keypair", func(t *testing.T) {
		t.Helper()
		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "wallet/test-generated",
			Storage:   storage,
		})

		assert.NoError(t, err)

		pk, err := solana.PublicKeyFromBase58(resp.Data["public_key"].(string))
		assert.NoError(t, err)
		assert.NotEmpty(t, pk.Bytes())
	})

	t.Run("Import Existing Private Key", func(t *testing.T) {
		t.Helper()

		wallet := solana.NewWallet()
		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "wallet/test-imported",
			Storage:   storage,
			Data: map[string]any{
				"private_key": wallet.PrivateKey.String(),
			},
		})

		assert.NoError(t, err)
		assert.Equal(t, wallet.PublicKey().String(), resp.Data["public_key"].(string))
	})
}

func TestWalletRead(t *testing.T) {
	backend, storage := getTestBackend(t)

	wallet := solana.NewWallet()

	t.Run("Read Public and Private Key Material", func(t *testing.T) {
		t.Helper()

		_, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "wallet/test",
			Storage:   storage,
			Data: map[string]any{
				"private_key": wallet.PrivateKey.String(),
			},
		})

		assert.NoError(t, err)

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "wallet/test",
			Storage:   storage,
		})

		assert.NoError(t, err)
		assert.Equal(t, wallet.PrivateKey.String(), resp.Data["private_key"].(string))
		assert.Equal(t, wallet.PublicKey().String(), resp.Data["public_key"].(string))
	})

	t.Run("Read Only Public Key", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "wallet/test/pubkey",
			Storage:   storage,
		})

		assert.NoError(t, err)
		assert.Nil(t, resp.Data["private_key"])
		assert.Len(t, resp.Data, 1)
		assert.Equal(t, wallet.PublicKey().String(), resp.Data["public_key"].(string))
	})

	t.Run("List Available Wallets", func(t *testing.T) {
		t.Helper()

		resp, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "wallets",
			Storage:   storage,
		})

		assert.NoError(t, err)
		assert.Len(t, resp.Data["keys"].([]string), 1)
	})
}
