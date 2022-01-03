package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/teris-io/cli"
	"log"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	RSA_KEY_LENGHT = 3072
	GROOT_CA_KEY   = "GrootCA.key"
	GROOT_CA_PUB   = "GrootCA.pub"
	GROOT_CA_CRT   = "GrootCA.crt"
)

type Session struct {
	caPriv    crypto.PrivateKey
	caPub     crypto.PublicKey
	caCert    *x509.Certificate
	log       *log.Logger
	caFolder  string
	hostnames []string
	outFolder string
}

const (
	KEY_TYPE   = "keyType"
	KT_RSA     = "RSA"
	KT_ECDSA   = "ECDSA"
	KT_ED25519 = "Ed25519"
	CA_PATH    = "path"
)

func main() {

	session := Session{}
	session.log = log.Default()

	initCA := cli.NewCommand("init-ca", "Generate a new CA").
		WithOption(cli.NewOption(KEY_TYPE, "RSA, ECDSA, Ed25519").WithChar('k').WithType(cli.TypeString)).
		WithArg(cli.NewArg(CA_PATH, "Path to CA directory")).
		WithAction(session.keyGen)

	genCert := cli.NewCommand("issue-cert", "Issue certs for hostname(s)").
		WithArg(cli.NewArg(CA_PATH, "Path to CA directory")).
		WithArg(cli.NewArg("hostnames", "List of hostnames separated by ','. First hostname will be used as folder name for certs and keys")).
		WithAction(session.createCert)

	app := cli.New("GrootCA is a minimalistic RootCA written in GO.").
		WithCommand(initCA).
		WithCommand(genCert)

	os.Exit(app.Run(os.Args, os.Stdout))
}

func (s *Session) createCert(args []string, options map[string]string) int {

	s.caFolder = args[0]
	exists, err := s.caExists()
	if err != nil || !exists {
		log.Printf("Error CA does not seem to exist: %v", err)
		return -1
	}

	s.hostnames = strings.Split(args[1], ",")
	s.outFolder = path.Join(s.caFolder, s.hostnames[0])
	if err := os.Mkdir(s.outFolder, 0700); err != nil {
		log.Printf("Error creating folder for cert: %v", err)
		return -1
	}
	log.Printf("Created %s as output location for certs", s.outFolder)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(512),
		Subject: pkix.Name{
			Organization: []string{s.hostnames[0]},
		},
		DNSNames:  s.hostnames,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageContentCommitment,
	}

	//Load CA Keys
	err = s.loadCA()
	if err != nil {
		log.Printf("Error reading CA Files: %v", err)
		return -1
	}

	privKey, pub := createRSAKeyForCA()

	if err := WritePrivateKey(privKey, path.Join(s.outFolder, s.hostnames[0]+".key")); err != nil {
		s.log.Printf("Error writing Private Key: %v", err)
		return -1
	}

	if err := WritePublicKey(pub, path.Join(s.outFolder, s.hostnames[0]+".pub")); err != nil {
		s.log.Printf("Error writing Private Key: %v", err)
		return -1
	}

	newCert, err := x509.CreateCertificate(rand.Reader, cert, s.caCert, pub, s.caPriv)
	if err != nil {
		panic(err)
	}

	if err := WritePEM(path.Join(s.outFolder, s.hostnames[0]+".crt"), CERTIFICATE, newCert); err != nil {
		s.log.Printf("Error writing cert: %s", err)
		return -1
	}

	return 0
}

func (s *Session) keyGen(args []string, options map[string]string) int {
	s.caFolder = args[0]
	exists, err := s.caExists()
	if err != nil {
		log.Printf("Error: %v", err)
		return -1
	}
	if !exists {
		log.Printf("No private key found in folder creating new CA")
		switch options[KEY_TYPE] {
		case KT_ECDSA:
			s.caPriv, s.caPub = createECDSAKeyForCA()
		case KT_RSA:
			s.caPriv, s.caPub = createRSAKeyForCA()
		case KT_ED25519:
			s.caPriv, s.caPub = createEd25519KeyForCA()
		default:
			s.log.Printf("No or not valid KeyType specified (%v). Falling back to RSA", options[KEY_TYPE])
			s.caPriv, s.caPub = createRSAKeyForCA()
		}
		s.persistKeys()
	} else {
		log.Printf("CA Exists. No need to initialize.")
		return 1
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"GrootCA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootCACert, err := x509.CreateCertificate(rand.Reader, ca, ca, s.caPub, s.caPriv)
	if err != nil {
		panic(err)
	}

	if err := WritePEM(path.Join(s.caFolder, GROOT_CA_KEY), CERTIFICATE, rootCACert); err != nil {
		s.log.Printf("Error writing Certificate: %v", err)
		return -1
	}
	return 0
}

func (s *Session) persistKeys() error {
	if err := WritePrivateKey(s.caPriv, path.Join(s.caFolder, GROOT_CA_KEY)); err != nil {
		return err
	}

	return WritePublicKey(s.caPub, path.Join(s.caFolder, GROOT_CA_PUB))
}

func (s *Session) caExists() (bool, error) {
	p, err := filepath.Abs(s.caFolder)
	if err != nil {
		return false, err
	}
	log.Printf("Looking for %s in %s", GROOT_CA_KEY, p)
	if _, err := os.Stat(p); err != nil {
		return false, err
	}
	if _, err := os.Stat(path.Join(p, GROOT_CA_KEY)); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *Session) loadCA() error {

	if privKey, err := LoadPrivateKeyPEM(path.Join(s.caFolder, GROOT_CA_KEY)); err != nil {
		return err
	} else {
		s.caPriv = privKey
	}

	if pubKey, err := LoadPublicKeyPEM(path.Join(s.caFolder, GROOT_CA_PUB)); err != nil {
		return err
	} else {
		s.caPub = pubKey
	}

	f, err := os.ReadFile(path.Join(s.caFolder, GROOT_CA_CRT))
	if err != nil {
		return err
	}

	block, _ := pem.Decode(f)
	s.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}
