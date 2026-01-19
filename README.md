# Vault Plugin: Solana Auth and Secrets Backend

This repository contains Vault plugin backends for both authentication and secrets engine functionality for Solana wallet keypairs.

## Downloads

The binaries and associated SHA256 sums for both plugin backends are prebuilt and uploaded in the repository releases for easy access and downloading. You can alternative build from source for your specific environment as well.

> [!IMPORTANT]
> If the execution environment is MacOs (`darwin`) and using the prebuilt binaries, then you'll likely have to adjust the Apple Quarantine attribute on binaries being used to allow execution because of the lack of Apple codesigning on the builds.
>
> ```bash
> $ xattr -d com.apple.quarantine vault-plugin-<TYPE>-solana
> ```

## Auth Backend

### Setup

```bash
$ vault plugin register \
    -sha256=$(shasum -a 256 vault-plugin-auth-solana | cut -d ' ' -f1) \
    auth \
    vault-plugin-auth-solana

$ vault auth enable -path=solana vault-plugin-auth-solana
```

### Usage

Authenticating with Vault using Solana offchain message verification is a 3 step process.

#### 1. Generate a random message/nonce to sign

```bash
$ MESSAGE=$(vault write -format=json auth/<MOUNT>/nonce public_key="<PUBKEY>" | jq -r .data.nonce)
```

#### 2. Sign the message with your keypair

```bash
$ SIGNATURE=$(solana sign-offchain-message --output json $MESSAGE)
```

#### 3. Login and verify with Vault

```bash
$ vault write auth/<MOUNT>/login public_key="<PUBKEY>" signature="$SIGNATURE"
```

> [!NOTE]
> This signature verification recreates the Solana V0 offchain message header preamble prior to verification
> to ensure compatibility with the signing/message standard used by the Solana CLI and SDKs.

## Secrets Backend

### Setup

```bash
$ vault plugin register \
    -sha256=$(shasum -a 256 vault-plugin-secrets-solana | cut -d ' ' -f1) \
    secret \
    vault-plugin-secrets-solana

$ vault secrets enable -path=solana vault-plugin-secrets-solana
```

## Build Source

The included `Makefile` in the repository contains a target to build the two backend binaries.

```bash
$ make build
```

This will produce the backend binaries at `./buld/plugins/vault-plugin-<TYPE>-solana` to be used with the Vault server.
