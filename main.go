package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const test3_privKey = "5f0241b62f29e52e7c8ad804862b6fd87d929a699b58a0b91bb08fae9dc76752"
const sender_address = "n15Exf2DuoDonkwAE571qhrFRGbrLhv9mU"
const receiver_address = "mkoZPNRwaw6PiryZN4xfv3ikfAZH5ixsfn"
const unspent_txo = "6b51e5318e7862d02683885c778a60d7422b08c4971988ba3548ca8f0cae149a"
const unspentSatoshi = 10000

type utxo struct {
	Address     string
	TxID        string
	OutputIndex uint32
	Script      []byte
	Satoshis    int64
}

func main() {

	// 1. Get address from your private key
	senderPrivateKey, fromAddress := GetKeyAddressFromPrivateKey(test3_privKey)
	fmt.Printf("TestNet3 Address: %s\n", fromAddress)
	if fromAddress != sender_address {
		log.Fatal("Wrong private key and address pair. Please recheck!")
	}

	// 2. Get some test-net-3 btc at https://coinfaucet.eu/en/btc-testnet/
	// 3. Create transaction

	unspentTx := utxo{
		Address:     sender_address,
		TxID:        unspent_txo,
		OutputIndex: 0,
		Script:      GetPayToAddrScript(receiver_address),
		Satoshis:    unspentSatoshi,
	}

	// create new empty transaction

	redemTx := wire.NewMsgTx(wire.TxVersion)

	hash, err := chainhash.NewHashFromStr(unspentTx.TxID)
	if err != nil {
		log.Fatalf("could not get hash from transaction ID: %v", err)
	}

	// create TxIn

	outPoint := wire.NewOutPoint(hash, unspentTx.OutputIndex)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	redemTx.AddTxIn(txIn)

	// create TxOut
	rcv_script := GetPayToAddrScript(receiver_address)
	outCoin := unspentTx.Satoshis

	txOut := wire.NewTxOut(outCoin, rcv_script)
	redemTx.AddTxOut(txOut)

	// sign transaction

	sig, err := txscript.SignatureScript(
		redemTx,             // The tx to be signed.
		0,                   // The index of the txin the signature is for.
		unspentTx.Script,    // The other half of the script from the PubKeyHash.
		txscript.SigHashAll, // The signature flags that indicate what the sig covers.
		senderPrivateKey,    // The key to generate the signature with.
		false)               // The compress sig flag. This saves space on the blockchain.

	if err != nil {
		log.Fatalf("could not generate signature: %v", err)
	}

	redemTx.TxIn[0].SignatureScript = sig

	//Validate signature
	flags := txscript.StandardVerifyFlags
	vm, err := txscript.NewEngine(unspentTx.Script, redemTx, 0, flags, nil, nil, outCoin)
	if err != nil {
		fmt.Printf("err != nil: %v\n", err)
	}
	if err := vm.Execute(); err != nil {
		fmt.Printf("vm.Execute > err != nil: %v\n", err)
	}

	fmt.Printf("redeemTx: %v\n", txToHex(redemTx))
}

func txToHex(tx *wire.MsgTx) string {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	tx.Serialize(buf)
	return hex.EncodeToString(buf.Bytes())
}

func GetPayToAddrScript(address string) []byte {
	rcvAddress, _ := btcutil.DecodeAddress(address, &chaincfg.TestNet3Params)
	rcvScript, _ := txscript.PayToAddrScript(rcvAddress)
	return rcvScript
}

func GenerateKeyAddress() ([]byte, string) {
	key, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		fmt.Printf("failed to make privKey for %s: %v", err)
	}

	pk := (*btcec.PublicKey)(&key.PublicKey).
		SerializeUncompressed()
	address, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pk), &chaincfg.TestNet3Params)
	keyBytes := key.Serialize()
	//keyHex := hex.EncodeToString(keyBytes)

	fmt.Printf("PrivateKey: %x \n", keyBytes)
	fmt.Printf("Address: %q\n", address.EncodeAddress())

	return keyBytes, address.EncodeAddress()
}

func GetKeyAddressFromPrivateKey(privKey string) (*btcec.PrivateKey, string) {
	privByte, err := hex.DecodeString(privKey)

	if err != nil {
		log.Panic(err)
	}

	priv, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privByte) //secp256k1

	address, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeUncompressed()), &chaincfg.TestNet3Params)

	return priv, address.EncodeAddress()
}
