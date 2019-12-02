package tools

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
)

// VaultClient points to vault Client
var VaultClient *api.Client // global variable

var vaultToken = os.Getenv("VAULT_TOKEN")
var vaultAddr = os.Getenv("VAULT_ADDR")

// InitVault initializes vault client
func InitVault(token string) error {
	conf := &api.Config{
		Address: vaultAddr,
	}

	client, err := api.NewClient(conf)
	if err != nil {
		return err
	}
	VaultClient = client

	VaultClient.SetToken(token)
	return nil
}

func main() {
	err := InitVault(vaultToken)
	if err != nil {
		log.Println(err)
	}
	c := VaultClient.Logical()

	pathArg := "cubbyhole/mysecret"
	secret, err := c.Write(pathArg,
		map[string]interface{}{
			"name":     "Louis",
			"username": "mod",
			"password": "pw",
		})
	if err != nil {
		log.Println(err)
	}
	log.Println(secret)
}
