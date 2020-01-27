package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/miquella/ssh-proxy-agent/lib/proxyagent"
)

// RootCLI is the root command for the `ssh-proxy-agent` entrypoint
var RootCLI = &cobra.Command{
	Use:   "ssh-proxy-agent",
	Short: "SSH-Proxy-Agent creates an ssh-agent proxy",

	RunE:         shellRunE,
	SilenceUsage: true,

	Version: "0.2.unstable",
}

var interactive bool

var generateKey bool
var noProxy bool
var validPrincipals []string
var vaultSigningUrl string

var shell = proxyagent.Spawn{}

func init() {
	RootCLI.Flags().BoolVarP(&interactive, "shell", "l", false, "spawn an interactive shell")

	RootCLI.Flags().BoolVar(&generateKey, "generate-key", false, "generate RSA key pair (default: false)")
	RootCLI.Flags().BoolVar(&noProxy, "no-proxy", false, "disable forwarding to an upstream agent (default: false)")
	RootCLI.Flags().StringSliceVar(&validPrincipals, "valid-principals", []string{os.Getenv("USER")}, "valid principals for Vault key signing")
	RootCLI.Flags().StringVar(&vaultSigningUrl, "vault-signing-url", "", "HashiCorp Vault url to sign SSH keys")
}

func shellRunE(cmd *cobra.Command, args []string) error {
	if !interactive {
		return cmd.Usage()
	}

	// TODO: handle creation of agent in a way that can be used by third-party tooling
	var keyring agent.Agent
	var err error
	if vaultSigningUrl != "" {
		if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
			vaultURL, vaultURLErr := url.Parse(vaultAddr)
			signingURL, signingURLErr := url.Parse(vaultSigningUrl)

			if vaultURLErr == nil && signingURLErr == nil {
				vaultSigningUrl = vaultURL.ResolveReference(signingURL).String()
			}
		}

		validPrincipalsString := strings.Join(validPrincipals, ",")
		keyring, err = proxyagent.NewSigningKeyring(vaultSigningUrl, validPrincipalsString)
		if err != nil {
			return err
		}
	} else {
		keyring = agent.NewKeyring()
	}

	upstreamAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if !noProxy && upstreamAuthSock != "" {
		var conn net.Conn
		conn, err = net.Dial("unix", upstreamAuthSock)
		if err != nil {
			return err
		}

		upstream := agent.NewClient(conn)
		shell.Agent = proxyagent.NewProxyKeyring(keyring, upstream)
	} else {
		shell.Agent = keyring
	}

	if generateKey {
		err = generateAndAddKey(keyring)
		if err != nil {
			return err
		}
	}

	shell.Command = loginShellCommand()
	return shell.Run()
}

func loginShellCommand() []string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	return []string{shell, "--login"}
}

// TODO: Move to a better spot, this is just for confirmation
type KeyPair struct {
	PrivateKey string
	PublicKey  string
	SignedKey  string
}

func generateAndAddKey(keyring agent.Agent) error {
	fmt.Println("Generating an RSA key...")
	keyPair, err := generateRSAKeyPair()
	if err != nil {
		return err
	}

	parsedKey, err := ssh.ParseRawPrivateKey([]byte(keyPair.PrivateKey))
	if err != nil {
		return err
	}

	return keyring.Add(agent.AddedKey{
		PrivateKey: parsedKey,
		Comment:    "ssh-proxy-agent-generated-key",
	})
}

func generateRSAKeyPair() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	var private bytes.Buffer
	err = pem.Encode(&private, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}

	pubkey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: string(private.Bytes()),
		PublicKey:  string(ssh.MarshalAuthorizedKey(pubkey)),
	}, nil
}
