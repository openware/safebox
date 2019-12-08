package vault

import (
	"fmt"
	"strconv"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/hashicorp/vault/api"
	"github.com/openware/safebox/pkg/env"
)

var vaultToken = env.FetchDefault("VAULT_TOKEN", "changeme")
var vaultAddr = env.FetchDefault("VAULT_ADDR", "http://localhost:8200")

const ChainExternal = uint32(0)
const ChainInternal = uint32(1)

type Vault struct {
	Client *api.Client
}

func New() (*Vault, error) {
	v := new(Vault)
	conf := &api.Config{
		Address: vaultAddr,
	}

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	v.Client = client
	v.Client.SetToken(vaultToken)
	return v, nil
}

func validateScope(scope string) error {
	if scope != "public" && scope != "private" {
		return fmt.Errorf("Unexpected scope: %s", scope)
	}
	return nil
}
func validateChain(chainID uint32) error {
	if chainID != ChainExternal && chainID != ChainInternal {
		return fmt.Errorf("Unexpected chainID: %d", chainID)
	}
	return nil
}

func vaultPathMasterKey(scope string, ccyCode string) (string, error) {
	if err := validateScope(scope); err != nil {
		return "", err
	}
	return fmt.Sprintf("cubbyhole/%s/%s/master/key", scope, ccyCode), nil
}

func vaultPathChain(scope string, ccyCode string, accountID uint, chainID uint32) (string, error) {
	if err := validateScope(scope); err != nil {
		return "", err
	}
	return fmt.Sprintf("cubbyhole/%s/%s/account/%d/%d", scope, ccyCode, accountID, chainID), nil
}

func vaultPathAccountKey(scope string, ccyCode string, accountID uint, chainID uint32, addID uint32) (string, error) {
	path, err := vaultPathChain(scope, ccyCode, accountID, chainID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d/key", path, addID), nil
}

func vaultPathChainIndex(scope string, ccyCode string, accountID uint, chainID uint32) (string, error) {
	path, err := vaultPathChain(scope, ccyCode, accountID, chainID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/index", path), nil
}

func vaultPathAccountIndex(scope string, ccyCode string, accountID uint, chainID uint32) (string, error) {
	path, err := vaultPathChain(scope, ccyCode, accountID, chainID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/index", path), nil
}

func (v *Vault) StoreChainIndex(index int, ccyCode string, accountID uint, chainID uint32) error {
	c := v.Client.Logical()
	path, err := vaultPathChainIndex("public", ccyCode, accountID, chainID)
	if err != nil {
		return err
	}

	_, err = c.Write(path,
		map[string]interface{}{
			"index": strconv.Itoa(index),
		})

	if err != nil {
		return err
	}

	return err
}

func (v *Vault) GetChainIndex(ccyCode string, accountID uint, chainID uint32) (int, error) {
	c := v.Client.Logical()
	path, err := vaultPathChainIndex("public", ccyCode, accountID, chainID)
	if err != nil {
		return -1, err
	}
	val, err := c.Read(path)
	if err != nil {
		return -1, err
	}
	if val == nil {
		return -2, fmt.Errorf("index not found")
	}
	index := val.Data["index"]
	if index == nil {
		return -2, fmt.Errorf("index not found in object")
	}
	return strconv.Atoi(fmt.Sprint(index))
}

func (v *Vault) StoreAccountAddress(key *hdkeychain.ExtendedKey, ccyCode string, accountID uint, chainID uint32, addID uint32) error {
	c := v.Client.Logical()
	path, err := vaultPathAccountKey("private", ccyCode, accountID, chainID, addID)
	if err != nil {
		return err
	}

	_, err = c.Write(path,
		map[string]interface{}{
			"priv": key.String(),
		})

	if err != nil {
		return err
	}

	path, err = vaultPathAccountKey("public", ccyCode, accountID, chainID, addID)
	if err != nil {
		return err
	}

	neuter, err := key.Neuter()
	if err != nil {
		return err
	}

	_, err = c.Write(path,
		map[string]interface{}{
			"pub": neuter.String(),
		})
	return err
}

func (v *Vault) GetPublicAddress(ccyCode string, accountID uint, chainID uint32, addID uint32) (*hdkeychain.ExtendedKey, error) {
	c := v.Client.Logical()
	path, err := vaultPathAccountKey("public", ccyCode, accountID, chainID, addID)
	if err != nil {
		return nil, err
	}
	val, err := c.Read(path)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, fmt.Errorf("public key not found")
	}
	pubStr := val.Data["pub"]
	if pubStr == nil {
		return nil, fmt.Errorf("public key not found")
	}
	return hdkeychain.NewKeyFromString(fmt.Sprint(pubStr))
}

func (v *Vault) GetPrivateAddress(codeCCY string, accountID uint, chainID uint32, addID uint32) (*hdkeychain.ExtendedKey, error) {
	c := v.Client.Logical()
	path, err := vaultPathAccountKey("private", codeCCY, accountID, chainID, addID)
	if err != nil {
		return nil, err
	}
	val, err := c.Read(path)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, fmt.Errorf("private key not found")
	}
	pubStr := val.Data["priv"]
	if pubStr == nil {
		return nil, fmt.Errorf("private key not found")
	}
	return hdkeychain.NewKeyFromString(fmt.Sprint(pubStr))
}

func (v *Vault) StoreMasterKey(masterKey *hdkeychain.ExtendedKey, codeCCY string) error {
	c := v.Client.Logical()
	path, err := vaultPathMasterKey("private", codeCCY)
	if err != nil {
		return err
	}
	_, err = c.Write(path,
		map[string]interface{}{
			"priv": masterKey.String(),
		})
	if err != nil {
		return err
	}

	path, err = vaultPathMasterKey("public", codeCCY)
	if err != nil {
		return err
	}

	neuter, err := masterKey.Neuter()
	if err != nil {
		return err
	}

	_, err = c.Write(path,
		map[string]interface{}{
			"pub": neuter.String(),
		})
	return err
}

func (v *Vault) GetMasterKeyPublic(codeCCY string) (*hdkeychain.ExtendedKey, error) {
	c := v.Client.Logical()
	path, err := vaultPathMasterKey("public", codeCCY)
	if err != nil {
		return nil, err
	}

	val, err := c.Read(path)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, fmt.Errorf("public master key not found")
	}
	keyStr := val.Data["pub"]
	if keyStr == nil {
		return nil, fmt.Errorf("public master key not found")
	}
	return hdkeychain.NewKeyFromString(fmt.Sprint(keyStr))
}

func (v *Vault) GetMasterKeyPrivate(codeCCY string) (*hdkeychain.ExtendedKey, error) {
	c := v.Client.Logical()
	path, err := vaultPathMasterKey("private", codeCCY)
	if err != nil {
		return nil, err
	}

	val, err := c.Read(path)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, fmt.Errorf("private master key not found")
	}
	keyStr := val.Data["priv"]
	if keyStr == nil {
		return nil, fmt.Errorf("private master key not found")
	}
	return hdkeychain.NewKeyFromString(fmt.Sprint(keyStr))
}
