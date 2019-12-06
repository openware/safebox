package tools

import (
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/hashicorp/vault/api"
	"github.com/openware/safebox/pkg/env"
)

// VaultClient points to vault Client
var VaultClient *api.Client // global variable

var vaultToken = env.FetchDefault("VAULT_TOKEN", "changeme")
var vaultAddr = env.FetchDefault("VAULT_ADDR", "http://localhost:8200")

const secretMasterKey = "cubbyhole/masterkey"

// InitVault initializes vault client
func InitVault() error {
	conf := &api.Config{
		Address: vaultAddr,
	}

	client, err := api.NewClient(conf)
	if err != nil {
		return err
	}
	VaultClient = client

	VaultClient.SetToken(vaultToken)
	return nil
}

func initVault(client *api.Client) {
	VaultClient = client
}

func StoreMasterKey(masterKey *hdkeychain.ExtendedKey) error {
	c := VaultClient.Logical()
	_, err := c.Write(secretMasterKey,
		map[string]interface{}{
			"key": masterKey.String(),
		})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func GetMasterKey() (*hdkeychain.ExtendedKey, error) {
	c := VaultClient.Logical()
	v, err := c.Read(secretMasterKey)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("value not found!")
	}
	keyInt := v.Data["key"]
	if keyInt == nil {
		return nil, fmt.Errorf("key not found")
	}

	return hdkeychain.NewKeyFromString(fmt.Sprintf("%v", keyInt))
}
