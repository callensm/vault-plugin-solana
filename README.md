<div align="center">
    <h1>Vault Plugin - Solana</h1>
    <p><strong>Offchain Message Auth and Keypair Secrets Backend</strong></p>
    <p>
        <a href="https://github.com/callensm/vault-plugin-solana/releases"><image alt="Releases" src="https://img.shields.io/github/v/release/callensm/vault-plugin-solana?color=lightgreen" /></a>
        <a href="https://github.com/callensm/vault-plugin-solana/actions"><image alt="Tests" src="https://github.com/callensm/vault-plugin-solana/actions/workflows/test.yaml/badge.svg" /></a>
        <a href="https://github.com/callensm/vault-plugin-solana/blob/master/LICENSE"><image alt="License" src="https://img.shields.io/badge/license-MPLv2.0-blue.svg" /></a>
    </p>
</div>

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

### Usage

#### Generate and store a new Solana wallet

```bash
$ vault write -force <mount>/wallet/my-wallet
```

#### Import an existing private key

```bash
$ vault write <mount>/wallet/my-wallet private_key="<BASE-58 PRIVKEY>"
```

#### List all stored wallets IDs

```bash
$ vault list <mount>/wallets
```

#### Read public and private key material in base-58

```bash
$ vault read <mount>/wallet/my-wallet
```

#### Read only the base-58 public key

```bash
$ vault read <mount>/wallet/my-wallet/pubkey
```

#### Sign a message

By default this message is signed _after_ being wrapped with the Solana V0 offchain message preamble. You can disable the offchain preamble and do a raw message signature by setting `offchain=false`.

```bash
$ vault write <mount>/wallet/my-wallet/message/sign message="my message body to sign" offchain=<bool>
```

#### Verify a message signature

Similarly with the signing write operation, you can disable the Solana V0 offchain message preamble during verification by setting `offchain=false`.

```bash
$ vault write <mount>/wallet/my-wallet/message/verify message="my message body to sign" signature="<BASE-58 SIGNATURE>" offchain=<bool>
```

## Build Source

The included `Makefile` in the repository contains a target to build the two backend binaries.

```bash
$ make build
```

This will produce the backend binaries at `./buld/plugins/vault-plugin-<TYPE>-solana` to be used with the Vault server.
