package main

import (
	"github.com/openware/safebox/pkg/api"
	"github.com/openware/safebox/pkg/env"
	"github.com/openware/safebox/pkg/vault"
	"log"
)

func initAuth() {
	fileName := env.FetchDefault("AUTH_PUBLIC_KEY_PATH", "./fixtures/sample.key.pub")
	api.LoadSigningKey(fileName)
}

func main() {
	initAuth()
	v, err := vault.New()
	if err != nil {
		log.Fatal(err)
		return
	}
	api.StartAPIServer(v)
}
