package main

import (
	"github.com/openware/safebox/pkg/api"
	"github.com/openware/safebox/pkg/env"
	"github.com/openware/safebox/pkg/tools"
)

func initAuth() {
	fileName := env.FetchDefault("AUTH_PUBLIC_KEY_PATH", "./fixtures/sample.key.pub")
	api.LoadSigningKey(fileName)
}

func main() {
	initAuth()
	tools.InitVault()
	api.StartAPIServer()
}
