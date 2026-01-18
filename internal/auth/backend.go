package auth

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/callensm/vault-plugin-solana/version"
)

const (
	backendHelp = `
The Solana auth backend allows for authentication and
Vault token issuance via message signature verification.
`
)

type AuthConfigEntry struct {
	TokenPolicies []string `json:"token_policies"`
	TokenTtl      int      `json:"token_ttl"`
	TokenMaxTtl   int      `json:"token_max_ttl"`
}

type NonceEntry struct {
	ExpiresAt int64  `json:"expires_at"`
	Nonce     string `json:"nonce"`
	PublicKey string `json:"public_key"`
}

type SolanaAuthBackend struct {
	*framework.Backend
}

func newSolanaAuthBackend() *SolanaAuthBackend {
	var s = SolanaAuthBackend{}
	s.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
			Unauthenticated: []string{
				"login",
				"nonce",
			},
		},
		Paths: []*framework.Path{
			pathConfig(&s),
			pathLogin(&s),
			pathNonce(&s),
		},
		BackendType:    logical.TypeCredential,
		RunningVersion: fmt.Sprintf("v%s", version.Version),
	}
	return &s
}
