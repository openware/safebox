package tools

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/docker/docker/pkg/testutil/assert"
	"github.com/hashicorp/vault/api"
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

func TestGetMasterKey(t *testing.T) {
	primary := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"key":"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"},"wrap_info":null,"warnings":null,"auth":null}`))
		w.WriteHeader(200)
	}
	config, ln := testHTTPServer(t, http.HandlerFunc(primary))
	defer ln.Close()

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	client.SetToken("foo")
	initVault(client)

	key, err := GetMasterKey("key", "cubbyhole/masterkey")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	assert.Equal(t,
		"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jP"+
			"PqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		key.String())

	key2, err2 := GetMasterKey("yek", "cubbyhole/masterkey")
	if err2 == nil {
		t.Fatalf("err: expected error hasn't occured")
	}

	assert.Error(t, err2, "such key doesn't exist!")
	assert.Equal(t, (*hdkeychain.ExtendedKey)(nil), key2)

	key3, err3 := GetMasterKey("key", "cubbyhole/minorkey")
	if err3 == nil {
		t.Fatalf("err: expected error hasn't occured")
	}

	assert.Error(t, err3, "path doesn't exist!")
	assert.Equal(t, (*hdkeychain.ExtendedKey)(nil), key3)

	// // Do a raw "/" request
	// resp, err := client.RawRequest(client.NewRequest("PUT", "/"))
	// if err != nil {
	// 	t.Fatalf("err: %s", err)
	// }

	// // Copy the response
	// var buf bytes.Buffer
	// io.Copy(&buf, resp.Body)

	// // Verify we got the response from the primary
	// if buf.String() != "test" {
	// 	t.Fatalf("Bad: %s", buf.String())
	// }
}
