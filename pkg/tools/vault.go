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

// chainId - shos if keypair is external (0) or internal (1)
const chainId = "0"

const secretMasterKey = "cubbyhole/masterkey"
const keyIndex = "0"
const priv = "MIIEpAIBAAKCAQEA0a4N1FmTAxDwnF6NuG5ZwV1pzaLA1w1UtUW6RbnP4Ymf4yFH" +
	"2m5qNWD/3VQK538Sj0uN66G59BzqstDrJ/9aMc7OczCP7xlhWV2qWqVTshbEhdMj" +
	"SR8nDp80mKanm9BNNULZpLF92NNLt/1Y/rKwpm+aEwCg6R4mnoLCRsVvsY3GImh/" +
	"byLswkS5OLWZRfyYvNMVS02ZpAqZmr6ZPE3lPLE6FGvEv6WFD3273lvfiNu7lxRs" +
	"LlfYknNVUinKAkA/1fsULuGkf93afthMHbKuMFRG6rY30D4R27fLuFTBw/IToCGh" +
	"L1Qynx8ohUsJSePAcQmuWsoyaD6NGbHXWs2f9QIDAQABAoIBAQCuTqQ+gExfQyjS" +
	"xSPJSysgPRikkwT+gZ2GqDWGm0Y+NtuMxHDoG9v9DesGQkRiV9fE+ck8NhDQ520Q" +
	"Q+8JLBT9zO8BAUDWQmIUGXJxsniWVqj+mxv9QIGGfUELGZfCRvK4MR+e8tIsetK6" +
	"XEksSr3hTmtmGqKpyJ/QK+F3VdBZZ4Eoef/bon4ZSLO7TFVcFeZLytVix7jXder6" +
	"XniTcyav7XS1TakCGRXKuVV/fWPqPjh5GsUxvAoVLsPLmed9VB39Ef4lgF7nvRzQ" +
	"3xnIDbXZbq1iqdLENt2ue0POCuOjMOF7vCDkbzUJNs+88zd7RR2wr8rrH0pg/W/M" +
	"zyzzY+QBAoGBAPl9lty+c6Pz8Y/8PjAqtUaKwxpM0fxEQUD8WL9Ho9LZtMOaprOX" +
	"40wN9zXJl18vSpAohqNTlpACQuNeeAl92g5u2JZy4FfwXgrSfTD327qGkZnvk0F0" +
	"i0xcpA+AESB675aKfcImHBcrKYfJBSkjP1HZoDihn2eF4B0HfeuunZ0BAoGBANcm" +
	"jyA7Zhwie5q0c8LacmTbNSXV6+yx+J1p7ZCbQopmibG4aK5F6Tbs3Sf0MNPcNaVm" +
	"OLlU65Vr/8dj2nx56cKimWZvW+8YMJSo9+eg5X7NGSoMtZzPtMYQNjp5AvX0PBRm" +
	"XTYNUiHVAtAr/AafheYZYYB17giX6UWkyhROUF71AoGBAOqj1vKcm52im5lTHhmm" +
	"0P4bGwrtHMAoYUaBDeY3tjdjUMJ1/DoDq12n9Mu9YIPAsluKAbYxsvSVa9ryyeoD" +
	"VsUkMsasG5oZEhkThXI8aYavcNhZnSB+P1P9/L4nL/RgKlxmu4eQ1/JiQZjW0eey" +
	"oqaUCj+4oXZ3TiN/HEo/2zQBAoGAJLjuIQBCc3bnRgaa451JfTF1JtoWhLXzy1pz" +
	"NAVsHBdYVT82jthb8AYJ0XH6i47AkVSbRfbapwxiAfRnLGvanGAIctV7CZpFYHpe" +
	"pehug3AaZXT54qQJJO1LdDuHZ9eiEZFPQ5SOejvTWRjI0ZCU2Cto2vZGBK15IWv5" +
	"GfIsAakCgYBUt2uHksEs6oDKpb/SP+k1jvqY72Ej3HzKFh9iBso4F4pWWhyvmFJH" +
	"XFYg4GBXyI7/dhUw/V7WLl2yjFqzQr21akDNor4yGDksYGpkxuJHdpA7f/NiWnrc" +
	"D5YNXMlFQwD6hCw29lPU8AnQy/OhOqWKj621F7SGTl5DD+Ns4qJjiA=="

const pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0a4N1FmTAxDwnF6NuG5Z" +
	"wV1pzaLA1w1UtUW6RbnP4Ymf4yFH2m5qNWD/3VQK538Sj0uN66G59BzqstDrJ/9a" +
	"Mc7OczCP7xlhWV2qWqVTshbEhdMjSR8nDp80mKanm9BNNULZpLF92NNLt/1Y/rKw" +
	"pm+aEwCg6R4mnoLCRsVvsY3GImh/byLswkS5OLWZRfyYvNMVS02ZpAqZmr6ZPE3l" +
	"PLE6FGvEv6WFD3273lvfiNu7lxRsLlfYknNVUinKAkA/1fsULuGkf93afthMHbKu" +
	"MFRG6rY30D4R27fLuFTBw/IToCGhL1Qynx8ohUsJSePAcQmuWsoyaD6NGbHXWs2f" +
	"9QIDAQAB"

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

func StoreKeyPair(masterKey *hdkeychain.ExtendedKey) error {
	c := VaultClient.Logical()
	_, err := c.Write("cubbyhole/"+masterKey.String()+"/"+keyIndex+chainId,
		map[string]interface{}{
			"pub":  pub,
			"priv": priv,
		})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func GetKeyPair(masterKey *hdkeychain.ExtendedKey) (string, string, error) {
	c := VaultClient.Logical()
	v, err := c.Read("cubbyhole/" + masterKey.String() + "/" + keyIndex + chainId)
	if err != nil {
		return "", "", err
	}
	if v == nil {
		return "", "", fmt.Errorf("value not found!")
	}
	pub1 := v.Data["pub"]
	if pub1 == nil {
		return "", "", fmt.Errorf("key not found")
	}
	priv1 := v.Data["priv"]
	if priv1 == nil {
		return "", "", fmt.Errorf("key not found")
	}

	return fmt.Sprintf("%v", v.Data["priv"]), fmt.Sprintf("%v", v.Data["pub"]), nil

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
