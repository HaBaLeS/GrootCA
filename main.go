package main

import (
	"github.com/HaBaLeS/GrootCA/grootca"
	"github.com/teris-io/cli"
	"log"
	"os"
)

func main() {

	session := grootca.Session{}
	session.Log = log.Default()

	initCA := cli.NewCommand("init-ca", "Generate a new CA").
		WithOption(cli.NewOption(grootca.KEY_TYPE, "RSA, ECDSA, Ed25519").WithChar('k').WithType(cli.TypeString)).
		WithArg(cli.NewArg(grootca.CA_PATH, "Path to CA directory")).
		WithAction(session.KeyGen)

	genCert := cli.NewCommand("issue-cert", "Issue certs for hostname(s)").
		WithArg(cli.NewArg(grootca.CA_PATH, "Path to CA directory")).
		WithArg(cli.NewArg("hostnames", "List of hostnames separated by ','. First hostname will be used as folder name for certs and keys")).
		WithAction(session.CreateCert)

	app := cli.New("GrootCA is a minimalistic RootCA written in GO.").
		WithCommand(initCA).
		WithCommand(genCert)

	os.Exit(app.Run(os.Args, os.Stdout))
}
