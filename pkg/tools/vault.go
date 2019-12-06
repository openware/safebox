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

var vaultToken = env.FetchDefault("VAULT_TOKEN", "changeme2")
var vaultAddr = env.FetchDefault("VAULT_ADDR", "http://localhost:8200")

const secretMasterKey = "cubbyhole/masterkey"

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

func GetMasterKey(s string, masterKeyPath string) (*hdkeychain.ExtendedKey, error) {
	c := VaultClient.Logical()
	v, err := c.Read(masterKeyPath)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("path doesn't exist!")
	}
	keyInt := v.Data[s]
	if keyInt == nil {
		return nil, fmt.Errorf("such key doesn't exist!")
	}

	return hdkeychain.NewKeyFromString(fmt.Sprintf("%v", keyInt))
}

// func main() {
// 	err := InitVault(vaultToken)
// 	if err != nil {
// 		log.Fatal(err)
// 		return
// 	}
// 	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
// 	masterSeed, err := hex.DecodeString(testVec1MasterHex)
// 	masterKey, err := hdkeychain.NewMaster(masterSeed, &chaincfg.MainNetParams)

// 	err = StoreMasterKey(masterKey)
// 	if err != nil {
// 		log.Fatal(err)
// 		return
// 	}
// 	masterKey2, err := GetMasterKey()
// 	if err != nil {
// 		log.Fatal(err)
// 		return
// 	}

// 	fmt.Println("Master key1: ", masterKey.String())
// 	fmt.Println("Master key2: ", masterKey2.String())
// }
