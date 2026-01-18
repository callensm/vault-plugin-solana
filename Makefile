build: clean
	go build -o build/plugins/vault-plugin-solana cmd/vault-plugin-solana/main.go

clean:
	rm -rf build/ vendor/

test:
	go test -v -cover ./internal/...

vendor: clean
	go mod tidy && go mod vendor

.PHONY: clean test vendor
