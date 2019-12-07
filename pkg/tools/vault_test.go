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

func testMasterKey(t *testing.T) *hdkeychain.ExtendedKey {
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	masterSeed, err := hex.DecodeString(testVec1MasterHex)
	assert.NoError(t, err)
	masterKey, err := hdkeychain.NewMaster(masterSeed, &chaincfg.MainNetParams)
	assert.NoError(t, err)
	return masterKey
}

func testAccountKey(t *testing.T) *hdkeychain.ExtendedKey {
	key, err := testMasterKey(t).Child(hdkeychain.HardenedKeyStart + 12)
	assert.NoError(t, err)
	return key
}

func testAccountAddressPrivate(t *testing.T, chainID uint8, addressID uint8) *hdkeychain.ExtendedKey {
	chainKey, err := testAccountKey(t).Child(uint32(chainID))
	assert.NoError(t, err)
	addressKey, err := chainKey.Child(uint32(addressID))
	assert.NoError(t, err)
	return addressKey
}

func testAccountAddressPublic(t *testing.T, chainID uint8, addressID uint8) *hdkeychain.ExtendedKey {
	chainKey, err := testAccountKey(t).Child(uint32(chainID))
	assert.NoError(t, err)
	chainNeuterKey, err := chainKey.Neuter()
	assert.NoError(t, err)
	addressKey, err := chainNeuterKey.Child(uint32(addressID))
	assert.NoError(t, err)
	return addressKey
}

var testMasterKeyString = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jP" +
	"PqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

func TestVaultPathMasterKey(t *testing.T) {
	t.Run("it returns public key path", func(t *testing.T) {
		path, err := vaultPathMasterKey("public", "abc")
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/public/abc/master/key", path)
	})

	t.Run("it returns private key path", func(t *testing.T) {
		path, err := vaultPathMasterKey("private", "abc")
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/private/abc/master/key", path)
	})

	t.Run("it returns an error when the scope is invalid", func(t *testing.T) {
		path, err := vaultPathMasterKey("invalid", "abc")
		assert.Error(t, err, "Unexpected scope: invalid")
		assert.Equal(t, "", path)
	})
}

func TestVaultPathChain(t *testing.T) {
	t.Run("it returns public chain path", func(t *testing.T) {
		path, err := vaultPathChain("public", "abc", 12, chainExternal)
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/public/abc/account/12/0", path)
	})

	t.Run("it returns private chain path", func(t *testing.T) {
		path, err := vaultPathChain("private", "abc", 12, chainInternal)
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/private/abc/account/12/1", path)
	})

	t.Run("it returns an error when the scope is invalid", func(t *testing.T) {
		path, err := vaultPathChain("invalid", "abc", 12, chainInternal)
		assert.Error(t, err, "Unexpected scope: invalid")
		assert.Equal(t, "", path)
	})
}

func TestVaultPathAccountKey(t *testing.T) {
	t.Run("it returns public account key", func(t *testing.T) {
		path, err := vaultPathAccountKey("public", "abc", 12, chainExternal, 21)
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/public/abc/account/12/0/21/key", path)
	})

	t.Run("it returns private account path", func(t *testing.T) {
		path, err := vaultPathAccountKey("private", "abc", 12, chainInternal, 21)
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/private/abc/account/12/1/21/key", path)
	})

	t.Run("it returns an error when the scope is invalid", func(t *testing.T) {
		path, err := vaultPathAccountKey("invalid", "abc", 12, chainInternal, 21)
		assert.Error(t, err, "Unexpected scope: invalid")
		assert.Equal(t, "", path)
	})
}

func TestVaultPathAccountIndex(t *testing.T) {
	t.Run("it returns public account key", func(t *testing.T) {
		path, err := vaultPathAccountIndex("public", "abc", 12, chainExternal)
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/public/abc/account/12/0/index", path)
	})

	t.Run("it returns private account path", func(t *testing.T) {
		path, err := vaultPathAccountIndex("private", "abc", 12, chainInternal)
		assert.NoError(t, err)
		assert.Equal(t, "cubbyhole/private/abc/account/12/1/index", path)
	})

	t.Run("it returns an error when the scope is invalid", func(t *testing.T) {
		path, err := vaultPathAccountIndex("invalid", "abc", 12, chainInternal)
		assert.Error(t, err, "Unexpected scope: invalid")
		assert.Equal(t, "", path)
	})
}

func TestStoreAccountAddress(t *testing.T) {
	chain := chainExternal
	accID := uint8(12)
	addID := uint8(42)
	privAddr := testAccountAddressPrivate(t, chain, addID)

	t.Run("Succeed to store the address", func(t *testing.T) {
		i := 0
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(204)
			switch i {
			case 0:
				assert.Equal(t, "/v1/cubbyhole/private/abc/account/12/0/42/key", req.RequestURI)
			case 1:
				assert.Equal(t, "/v1/cubbyhole/public/abc/account/12/0/42/key", req.RequestURI)
			default:
				assert.Fail(t, "server called more than 2 times")
			}
			i++
		})
		defer ln.Close()
		err := StoreAccountAddress(privAddr, "abc", accID, chain, addID)
		assert.NoError(t, err)
	})

	t.Run("Authentication fails", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`{"errors":["permission denied"]}`))
		})
		defer ln.Close()

		err := StoreAccountAddress(privAddr, "abc", accID, chain, addID)
		assert.Error(t, err, "Error making API request.")
	})
}

func TestGetMasterKeyPrivate(t *testing.T) {
	t.Run("Succeed to fetch the token", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, "/v1/cubbyhole/private/btc/master/key", req.RequestURI)
			w.WriteHeader(200)
			w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"priv":"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"},"wrap_info":null,"warnings":null,"auth":null}`))
		})
		defer ln.Close()

		key, err := GetMasterKeyPrivate()
		assert.NoError(t, err)
		assert.Equal(t, testMasterKeyString, key.String())
	})

	t.Run("Wrong storage format", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"key":"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"},"wrap_info":null,"warnings":null,"auth":null}`))
		})
		defer ln.Close()

		key, err := GetMasterKeyPrivate()
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("Authentication fails", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`{"errors":["permission denied"]}`))
		})
		defer ln.Close()

		key, err := GetMasterKeyPrivate()
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

		err := StoreMasterKey(testMasterKey(t))
		assert.NoError(t, err)
	})

	t.Run("Authentication fails", func(t *testing.T) {
		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`{"errors":["permission denied"]}`))
		})
		defer ln.Close()

		err := StoreMasterKey(testMasterKey(t))
		assert.Error(t, err, "Error making API request.")
	})
}

// func TestGetKeyPair(t *testing.T) {
// 	t.Run("Succeed to fech the private and public keys", func(t *testing.T) {
// 		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
// 			w.WriteHeader(200)
// 			w.Write([]byte(`{"request_id":"518af827-c7d4-8ac8-2202-061ea530466d","lease_id":"","renewable":false,"lease_duration":0,"data":{"pub":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0a4N1FmTAxDwnF6NuG5Z
// 			wV1pzaLA1w1UtUW6RbnP4Ymf4yFH2m5qNWD/3VQK538Sj0uN66G59BzqstDrJ/9a
// 			Mc7OczCP7xlhWV2qWqVTshbEhdMjSR8nDp80mKanm9BNNULZpLF92NNLt/1Y/rKw
// 			pm+aEwCg6R4mnoLCRsVvsY3GImh/byLswkS5OLWZRfyYvNMVS02ZpAqZmr6ZPE3l
// 			PLE6FGvEv6WFD3273lvfiNu7lxRsLlfYknNVUinKAkA/1fsULuGkf93afthMHbKu
// 			MFRG6rY30D4R27fLuFTBw/IToCGhL1Qynx8ohUsJSePAcQmuWsoyaD6NGbHXWs2f
// 			9QIDAQAB", "priv":"MIIEpAIBAAKCAQEA0a4N1FmTAxDwnF6NuG5ZwV1pzaLA1w1UtUW6RbnP4Ymf4yFH
// 			2m5qNWD/3VQK538Sj0uN66G59BzqstDrJ/9aMc7OczCP7xlhWV2qWqVTshbEhdMj
// 			SR8nDp80mKanm9BNNULZpLF92NNLt/1Y/rKwpm+aEwCg6R4mnoLCRsVvsY3GImh/
// 			byLswkS5OLWZRfyYvNMVS02ZpAqZmr6ZPE3lPLE6FGvEv6WFD3273lvfiNu7lxRs
// 			LlfYknNVUinKAkA/1fsULuGkf93afthMHbKuMFRG6rY30D4R27fLuFTBw/IToCGh
// 			L1Qynx8ohUsJSePAcQmuWsoyaD6NGbHXWs2f9QIDAQABAoIBAQCuTqQ+gExfQyjS
// 			xSPJSysgPRikkwT+gZ2GqDWGm0Y+NtuMxHDoG9v9DesGQkRiV9fE+ck8NhDQ520Q
// 			Q+8JLBT9zO8BAUDWQmIUGXJxsniWVqj+mxv9QIGGfUELGZfCRvK4MR+e8tIsetK6
// 			XEksSr3hTmtmGqKpyJ/QK+F3VdBZZ4Eoef/bon4ZSLO7TFVcFeZLytVix7jXder6
// 			XniTcyav7XS1TakCGRXKuVV/fWPqPjh5GsUxvAoVLsPLmed9VB39Ef4lgF7nvRzQ
// 			3xnIDbXZbq1iqdLENt2ue0POCuOjMOF7vCDkbzUJNs+88zd7RR2wr8rrH0pg/W/M
// 			zyzzY+QBAoGBAPl9lty+c6Pz8Y/8PjAqtUaKwxpM0fxEQUD8WL9Ho9LZtMOaprOX
// 			40wN9zXJl18vSpAohqNTlpACQuNeeAl92g5u2JZy4FfwXgrSfTD327qGkZnvk0F0
// 			i0xcpA+AESB675aKfcImHBcrKYfJBSkjP1HZoDihn2eF4B0HfeuunZ0BAoGBANcm
// 			jyA7Zhwie5q0c8LacmTbNSXV6+yx+J1p7ZCbQopmibG4aK5F6Tbs3Sf0MNPcNaVm
// 			OLlU65Vr/8dj2nx56cKimWZvW+8YMJSo9+eg5X7NGSoMtZzPtMYQNjp5AvX0PBRm
// 			XTYNUiHVAtAr/AafheYZYYB17giX6UWkyhROUF71AoGBAOqj1vKcm52im5lTHhmm
// 			0P4bGwrtHMAoYUaBDeY3tjdjUMJ1/DoDq12n9Mu9YIPAsluKAbYxsvSVa9ryyeoD
// 			VsUkMsasG5oZEhkThXI8aYavcNhZnSB+P1P9/L4nL/RgKlxmu4eQ1/JiQZjW0eey
// 			oqaUCj+4oXZ3TiN/HEo/2zQBAoGAJLjuIQBCc3bnRgaa451JfTF1JtoWhLXzy1pz
// 			NAVsHBdYVT82jthb8AYJ0XH6i47AkVSbRfbapwxiAfRnLGvanGAIctV7CZpFYHpe
// 			pehug3AaZXT54qQJJO1LdDuHZ9eiEZFPQ5SOejvTWRjI0ZCU2Cto2vZGBK15IWv5
// 			GfIsAakCgYBUt2uHksEs6oDKpb/SP+k1jvqY72Ej3HzKFh9iBso4F4pWWhyvmFJH
// 			XFYg4GBXyI7/dhUw/V7WLl2yjFqzQr21akDNor4yGDksYGpkxuJHdpA7f/NiWnrc
// 			D5YNXMlFQwD6hCw29lPU8AnQy/OhOqWKj621F7SGTl5DD+Ns4qJjiA=="},"wrap_info":null,"warnings":null,"auth":null}`))
// 		})
// 		defer ln.Close()

// 		priv1, pub1, err := GetKeyPair(testMasterKey())
// 		assert.NoError(t, err)
// 		assert.Equal(t, priv, priv1)
// 		assert.Equal(t, pub, pub1)
// 	})

// 	t.Run("Authentication fails", func(t *testing.T) {
// 		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
// 			w.WriteHeader(403)
// 			w.Write([]byte(`{"errors":["permission denied"]}`))
// 		})
// 		defer ln.Close()

// 		priv1, pub1, err := GetKeyPair(testMasterKey())
// 		assert.Error(t, err, "Error making API request.")
// 		assert.Nil(t, priv1)
// 		assert.Nil(t, pub1)
// 	})
// }

// func TestStoreKeyPair(t *testing.T) {
// 	t.Run("Succeed to store private and public keys", func(t *testing.T) {
// 		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
// 			w.WriteHeader(204)
// 		})
// 		defer ln.Close()

// 		err := StoreKeyPair(testMasterKey())
// 		assert.NoError(t, err)
// 	})

// 	t.Run("Authentication fails", func(t *testing.T) {
// 		ln := testVaultClient(t, func(w http.ResponseWriter, req *http.Request) {
// 			w.WriteHeader(403)
// 			w.Write([]byte(`{"errors":["permission denied"]}`))
// 		})
// 		defer ln.Close()

// 		err := StoreKeyPair(testMasterKey())
// 		assert.Error(t, err, "Error making API request.")
// 	})
// }
