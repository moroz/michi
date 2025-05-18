package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/argon2"
)

var ORDER_IDS = []string{
	"0196e3fc-e45c-7460-888a-f3101e557498",
	"0196e3fd-3221-7cf7-a8e2-4a7095c98a7f",
	"0196e3fd-4fdc-7920-9c4d-262a634657f1",
}

func deriveKey(base *hdkeychain.ExtendedKey, path ...uint32) (key *hdkeychain.ExtendedKey, err error) {
	key = base
	for _, idx := range path {
		key, err = key.Derive(idx)
		if err != nil {
			return
		}
	}
	return
}

func MustGetenv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("FATAL: Environment variable %s is not defined!", key)
	}
	return val
}

func MustGetenvBase64(key string) []byte {
	val := MustGetenv(key)
	bytes, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		log.Fatalf("FATAL: Failed to decode environment variable %s from Base64!", key)
	}
	return bytes
}

var SECRET_KEY_BASE = MustGetenvBase64("SECRET_KEY_BASE")
var NEUTERED_BASE_KEY = MustGetenv("NEUTERED_BASE_KEY")

var HMAC_KEY = argon2.IDKey(SECRET_KEY_BASE, []byte("derivation path"), 2, 46*1024, 1, 32)

func bytesToIndex(slices ...[]byte) []uint32 {
	var results = make([]uint32, len(slices))
	for i, slice := range slices {
		var val uint32
		binary.Decode(slice, binary.LittleEndian, &val)
		results[i] = val & 0x7F_FF_FF_FF
	}
	return results
}

func orderIDToPath(orderID []byte) []uint32 {
	mac := hmac.New(sha256.New, HMAC_KEY)
	mac.Write(orderID)
	sum := mac.Sum(nil)
	return bytesToIndex(sum[:4], sum[len(sum)-4:])
}

func main() {
	baseKey, err := hdkeychain.NewKeyFromString(NEUTERED_BASE_KEY)
	if err != nil {
		log.Fatal(err)
	}
	_ = baseKey

	for _, id := range ORDER_IDS {
		uuid, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Order ID: %X\n", uuid)

		path := orderIDToPath(uuid)
		fmt.Println(path)

		derived, err := deriveKey(baseKey, path...)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("m/69'/0'/0'/%d/%d\n", path[0], path[1])

		pubKey, err := derived.ECPubKey()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Public key: %X\n", pubKey.SerializeCompressed())

		witnessProg := btcutil.Hash160(pubKey.SerializeCompressed())
		addr, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(addr.EncodeAddress())

		fmt.Println()
	}

}
