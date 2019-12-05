package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
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

func storeMasterKey(masterKey *hdkeychain.ExtendedKey) error {
	pathArg := "cubbyhole/masterkey"
	c := VaultClient.Logical()
	_, err := c.Write(pathArg,
		map[string]interface{}{
			"key": masterKey.String(),
		})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func getMasterKey() (interface{}, error) {
	pathArg := "cubbyhole/masterkey"

	c := VaultClient.Logical()
	v, err := c.Read(pathArg)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	if v == nil {
		return nil, fmt.Errorf("value not found!")
	}
	if _, err := v.Data["key"]; !err {
		return nil, fmt.Errorf("such key doesn't exist!")
	}
	return v.Data["key"], nil
}

func main() {
	err := InitVault(vaultToken)
	if err != nil {
		log.Println(err)
		return
	}
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	masterSeed, err := hex.DecodeString(testVec1MasterHex)
	masterKey, err := hdkeychain.NewMaster(masterSeed, &chaincfg.MainNetParams)

	storeMasterKey(masterKey)
	masterKey2, _ := getMasterKey()

	masterKey2 = fmt.Sprintf("%v", masterKey2)

	fmt.Println("Master key1: ", masterKey.String())
	fmt.Println("Master key2: ", masterKey2)
}
