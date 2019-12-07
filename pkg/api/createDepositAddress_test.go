package api

import "testing"

import "github.com/stretchr/testify/assert"

// func TestCreateDepositAddressParseParamsSuccess(t *testing.T) {
// 	data := []byte(`{
// 		"account_id": 0,
// 		"driver": "btc",
// 		"uid": "U0000001111",
// 	}`)
// 	assert.NotNil(t, data)

// 	expectedReturn := []byte(`{
// 		address: "fakeAddress",
// 		details: {
// 			uid: "U0000001111"
// 			ex_address_id: 42
// 		}
// 	}`)
// 	assert.NotNil(t, expectedReturn)
// }

func TestCreateDepositAddressParams(t *testing.T) {
	t.Run("valid input", func(t *testing.T) {
		data := []byte(`{
			"account_id": 3,
			"driver": "btc",
			"uid": "U0000001111",
		}`)
		p, err := parseCreateDepositAddressParams(data)
		if assert.NoError(t, err) {
			assert.Equal(t, int32(3), p.AccountID)
			assert.Equal(t, "btc", p.Driver)
			assert.Equal(t, "U0000001111", p.UID)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		data := []byte(`{
			"account_id": 3,
			"driver": "btc",
			"uid": "U0000001111",
		`)
		p, err := parseCreateDepositAddressParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "Value is array, but can't find closing ']' symbol")
		assert.Nil(t, p)
	})

	t.Run("missing account_id", func(t *testing.T) {
		data := []byte(`{
			"driver": "btc",
			"uid": "U0000001111",
		}`)
		p, err := parseCreateDepositAddressParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "account_id is missing")
		assert.Nil(t, p)
	})

	t.Run("negative account_id", func(t *testing.T) {
		data := []byte(`{
			"account_id": -3,
			"driver": "btc",
			"uid": "U0000001111",
		}`)
		p, err := parseCreateDepositAddressParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "Invalid account_id")
		assert.Nil(t, p)
	})

	t.Run("out int boundaries account_id", func(t *testing.T) {
		data := []byte(`{
			"account_id": 2147483648,
			"driver": "btc",
			"uid": "U0000001111",
		}`)
		p, err := parseCreateDepositAddressParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "Invalid account_id")
		assert.Nil(t, p)
	})

	t.Run("missing driver", func(t *testing.T) {
		data := []byte(`{
			"account_id": 3,
			"uid": "U0000001111",
		}`)
		p, err := parseCreateDepositAddressParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "driver is missing")
		assert.Nil(t, p)
	})

	t.Run("missing uid", func(t *testing.T) {
		data := []byte(`{
			"account_id": 3,
			"driver": "btc",
		}`)
		p, err := parseCreateDepositAddressParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "uid is missing")
		assert.Nil(t, p)
	})
}
