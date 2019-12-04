package api

import "testing"

import "github.com/stretchr/testify/assert"

func TestTransferParseParamsSuccess(t *testing.T) {
	data := []byte(`{
		"wallet_id":  "xpub...",
		"account_id": 0,
		"driver": "btc",
		"to_address": "0x123456789acb",
		"amount": "1.123456",
	}`)
	assert.NotNil(t, data)

	expectedReturn := []byte(`{
		hash: "0x987654321"
	}`)
	assert.NotNil(t, expectedReturn)
}
