package grootca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"log"
)

func createRSAKeyForCA() (crypto.PrivateKey, crypto.PublicKey) {
	log.Printf("Creating new RSA key with %d bits\n", RSA_KEY_LENGHT)
	pk, err := rsa.GenerateKey(rand.Reader, RSA_KEY_LENGHT)
	if err != nil {
		panic(err)
	}
	return crypto.PrivateKey(pk), pk.Public()
}

func createECDSAKeyForCA() (crypto.PrivateKey, crypto.PublicKey) {
	log.Printf("Creating new ECDSA key with Curve P265\n")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return crypto.PrivateKey(pk), pk.Public()
}

func createEd25519KeyForCA() (crypto.PrivateKey, crypto.PublicKey) {
	log.Printf("Creating new Ed25519 key\n")
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return crypto.PrivateKey(pk), pub
}
