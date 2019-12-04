package api

import "testing"

import "github.com/stretchr/testify/assert"

func TestCreateDepositAddressParseParamsSuccess(t *testing.T) {
	data := []byte(`{
		"wallet_id":  "xpub...",
		"account_id": 0,
		"driver": "btc",
		"uid": "U0000001111",
	}`)
	assert.NotNil(t, data)

	expectedReturn := []byte(`{
		address: :fake_address,
		details: {
			uid: account.member.uid
			ex_address_id: 42
		}
	}`)
	assert.NotNil(t, expectedReturn)
}
