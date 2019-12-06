package api

import "testing"

import (
"github.com/stretchr/testify/assert"
)

func TestGetBalanceParseParamsSuccess(t *testing.T) {
	data := []byte(`{
		"wallet_id":  "xpub...",
		"account_id": 0,
		"driver": "btc",
	}`)
	assert.NotNil(t, data)

	expectedReturn := []byte(`{
		balance: 123456789.123456
	}`)
	assert.NotNil(t, expectedReturn)
}
