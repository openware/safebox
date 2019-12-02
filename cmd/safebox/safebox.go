package main

import (
	"github.com/openware/safebox/pkg/api"
	"github.com/openware/safebox/pkg/env"
)

func initAuth() {
	fileName := env.FetchDefault("AUTH_PUBLIC_KEY_PATH", "./fixtures/sample.key.pub")
	api.LoadSigningKey(fileName)
}

func main() {
	initAuth()
	api.StartAPIServer()
}
