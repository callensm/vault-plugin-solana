#!/bin/bash

export VAULT_ADDR="http://127.0.0.1:8200"

SHASUM=$(shasum -a 256 build/plugins/vault-plugin-secrets-solana | cut -d ' ' -f1)
INIT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
UNSEAL_KEY=$(echo "$INIT" | jq -r .unseal_keys_b64.[0])

export VAULT_TOKEN=$(echo "$INIT" | jq -r .root_token)

vault operator unseal $UNSEAL_KEY
vault plugin register -sha256=$SHASUM secret vault-plugin-secrets-solana
vault secrets enable -path=solana vault-plugin-secrets-solana

echo ""
echo "export VAULT_ADDR=\"http://127.0.0.1:8200\""
echo "export VAULT_TOKEN=$VAULT_TOKEN"
