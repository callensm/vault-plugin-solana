package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	"github.com/callensm/vault-plugin-solana"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: solana.AuthFactory,
		TLSProviderFunc:    tlsProviderFunc,
	})

	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("solana auth plugin shutting down", "error", err)
		os.Exit(1)
	}
}
