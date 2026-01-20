build: clean
	go build -o build/plugins/vault-plugin-auth-solana cmd/vault-plugin-auth-solana/main.go
	go build -o build/plugins/vault-plugin-secrets-solana cmd/vault-plugin-secrets-solana/main.go

clean:
	rm -rf build/ vendor/

test:
	go test -v ./internal/...

vendor: clean
	go mod tidy && go mod vendor

.PHONY: clean test vendor
