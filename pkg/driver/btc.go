package driver

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/openware/safebox/pkg/tools"
)

type CreateDepositAddressParams struct {
	AccountID int32  `json:"account_id"`
	Driver    string `json:"driver"`
	UID       string `json:"uid"`
}

type DepositAddress struct {
	Address string      `json:"address"`
	Details interface{} `json:"details"`
}

type DepositAddressDetails struct {
	UID         string `json:"uid"`
	ExAddressID uint32 `json:"ex_address_id"`
}

type GenericDriver interface {
	CreateDepositAddress(*CreateDepositAddressParams) (*DepositAddress, error)
	CreateMasterKey() error
}

type BTC struct {
	codeCCY string
}

func NewBTC(codeCCY string) *BTC {
	d := new(BTC)
	d.codeCCY = codeCCY
	return d
}

func (d *BTC) CreateDepositAddress(p *CreateDepositAddressParams) (*DepositAddress, error) {
	add := &DepositAddress{}
	idx, err := tools.GetChainIndex(d.codeCCY, uint(p.AccountID), tools.ChainExternal)

	if err != nil {
		if idx != -2 {
			return nil, err
		}
		idx = 0
	}
	if idx < 0 {
		return nil, fmt.Errorf("Chain index can't be negative")
	}
	if p.AccountID < 0 {
		return nil, fmt.Errorf("Account ID can't be negative")
	}

	masterKeyNeuter, err := tools.GetMasterKeyPublic(d.codeCCY)
	if err != nil {
		return nil, err
	}

	// This gives the path: M/xH
	acc, err := masterKeyNeuter.Child(uint32(p.AccountID))
	if err != nil {
		return nil, err
	}

	// This gives the path: M/xH/0
	accExt, err := acc.Child(tools.ChainExternal)
	if err != nil {
		return nil, err
	}

	// This gives the path: M/xH/0/y
	accExtN, err := accExt.Child(uint32(idx))
	if err != nil {
		return nil, err
	}

	acctExtNAddr, err := accExtN.Address(&chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	add.Address = acctExtNAddr.String()
	add.Details = DepositAddressDetails{
		UID:         p.UID,
		ExAddressID: uint32(idx),
	}
	err = tools.StoreChainIndex(idx+1, d.codeCCY, uint(p.AccountID), tools.ChainExternal)
	if err != nil {
		return nil, err
	}

	return add, nil
}

func (d *BTC) CreateMasterKey() error {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return err
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	tools.StoreMasterKey(masterKey, d.codeCCY)
	return nil
}
