package driver

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/openware/safebox/pkg/env"
	"github.com/openware/safebox/pkg/vault"
	"github.com/stretchr/testify/assert"
)

var vaultToken = env.FetchDefault("VAULT_TOKEN", "")
var vaultAddr = env.FetchDefault("VAULT_ADDR", "")

func testVaultClient(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (net.Listener, *vault.Vault) {
	config, ln := testHTTPServer(t, http.HandlerFunc(handler))
	client, err := api.NewClient(config)
	assert.NoError(t, err)
	client.SetToken("foo")
	v := &vault.Vault{
		Client: client,
	}
	return ln, v
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

func TestCreateMasterKey(t *testing.T) {

	d := NewBTC("btc")
	assert.NotNil(t, d, "driver initiazlization failed")

	t.Run("valid MasterKey creation", func(t *testing.T) {
		ln, v := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"priv":""},"wrap_info":null,"warnings":null,"auth":null}`))
		})
		defer ln.Close()
		d.vault = v
		err := d.CreateMasterKey()
		assert.Nil(t, err, "MasterKey creation failed")
	})

	t.Run("invalid creation of second MasterKey", func(t *testing.T) {
		ln, v := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"priv":"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"},"wrap_info":null,"warnings":null,"auth":null}`))
		})
		defer ln.Close()
		d.vault = v
		err := d.CreateMasterKey()
		assert.Error(t, err, "Second MasterKey creation should be failed")
	})
}
