package grootca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type PEMType string

const (
	PRIVATE_KEY PEMType = "PRIVATE KEY"
	PUBLIC_KEY  PEMType = "PUBLIC KEY"
	CERTIFICATE PEMType = "CERTIFICATE"
)

func WritePublicKey(key crypto.PublicKey, name string) error {
	asn1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	if err := WritePEM(name, PUBLIC_KEY, asn1); err != nil {
		return err
	}
	return nil
}
func WritePrivateKey(key crypto.PrivateKey, name string) error {
	asn1, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := WritePEM(name, PRIVATE_KEY, asn1); err != nil {
		return err
	}
	return nil
}

func WritePEM(name string, t PEMType, data []byte) error {
	b := pem.EncodeToMemory(&pem.Block{
		Type:  string(t),
		Bytes: data,
	})
	if err := os.WriteFile(name, b, 0700); err != nil {
		return err
	}
	return nil
}

func LoadPrivateKeyPEM(file string) (crypto.PrivateKey, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(f)
	if block == nil {
		return nil, fmt.Errorf("could not parse PEM file: %v. No PEM data found", file)
	}
	privKey, asn1err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if asn1err != nil {
		return nil, asn1err
	}
	return crypto.PrivateKey(privKey), nil
}

func LoadPublicKeyPEM(file string) (crypto.PublicKey, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(f)
	if block == nil {
		return nil, fmt.Errorf("could not parse PEM file: %v. No PEM data found", file)
	}
	pubKey, asn1err := x509.ParsePKIXPublicKey(block.Bytes)
	if asn1err != nil {
		return nil, asn1err
	}
	return crypto.PublicKey(pubKey), nil
}
