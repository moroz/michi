package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

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

// Generates a master seed (32 bytes) and a neutered extended key with the derivation path of m/69'/0'/0'.
// Outputs both as a shell script template for use with direnv.

func main() {
	var seed = make([]byte, 32)
	rand.Read(seed)
	fmt.Printf(`export MASTER_SEED="%s"`+"\n", base64.StdEncoding.EncodeToString(seed))

	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		log.Fatal(err)
	}

	derived, err := deriveKey(
		master,
		hdkeychain.HardenedKeyStart+69,
		hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		log.Fatal(err)
	}

	derived, err = derived.Neuter()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf(`export NEUTERED_BASE_KEY="%s"`+"\n", derived.String())
}
