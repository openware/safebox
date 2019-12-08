package api

import "testing"

import "github.com/stretchr/testify/assert"

func TestParseCreateMasterKeyParams(t *testing.T) {
	data := []byte(`{
		"driver": "btc",
	}`)
	assert.NotNil(t, data)

	t.Run("valid input", func(t *testing.T) {
		data := []byte(`{
			"driver": "btc",
		}`)
		p, err := parseCreateMasterKeyParams(data)
		if assert.NoError(t, err) {
			assert.Equal(t, "btc", p.Driver)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		data := []byte(`"driver": "btc",`)
		p, err := parseCreateMasterKeyParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "Key driver not found")
		assert.Nil(t, p)
	})

	t.Run("missing account_id", func(t *testing.T) {
		data := []byte(`{
			"driverz": "btc",
		}`)
		p, err := parseCreateMasterKeyParams(data)
		assert.Error(t, err)
		assert.EqualError(t, err, "Key driver not found")
		assert.Nil(t, p)
	})
}
