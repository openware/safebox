package tools

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Ensure our special envvars are not present
	os.Setenv("VAULT_ADDR", "")
	os.Setenv("VAULT_TOKEN", "")
}

func testHTTPServer(
	t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	server := &http.Server{Handler: handler}
	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln
}

func testVaultClient(t *testing.T, handler func(http.ResponseWriter, *http.Request)) net.Listener {
	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	client, err := api.NewClient(config)
	assert.NoError(t, err)
	client.SetToken("foo")
	initVault(client)
	return ln
}

func testMasterKey() *hdkeychain.ExtendedKey {
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	masterSeed, _ := hex.DecodeString(testVec1MasterHex)
	masterKey, _ := hdkeychain.NewMaster(masterSeed, &chaincfg.MainNetParams)
	return masterKey
}

var testMasterKeyString = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jP" +
	"PqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

func TestGetMasterKey(t *testing.T) {
	t.Run("Succeed to fech the token", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"key":"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"},"wrap_info":null,"warnings":null,"auth":null}`))
		})
		defer ln.Close()

		key, err := GetMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, testMasterKeyString, key.String())
	})

	t.Run("Authentication fails", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`{"errors":["permission denied"]}`))
		})
		defer ln.Close()

		key, err := GetMasterKey()
		assert.Error(t, err, "Error making API request.")
		assert.Nil(t, key)
	})
}

func TestStoreMasterKey(t *testing.T) {
	t.Run("Succeed to store the token", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(204)
		})
		defer ln.Close()

		err := StoreMasterKey(testMasterKey())
		assert.NoError(t, err)
	})

	t.Run("Authentication fails", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`{"errors":["permission denied"]}`))
		})
		defer ln.Close()

		err := StoreMasterKey(testMasterKey())
		assert.Error(t, err, "Error making API request.")
	})
}
