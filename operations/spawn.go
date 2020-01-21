package operations

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	proxyagent "github.com/miquella/ssh-proxy-agent/lib"
)

// Spawn contains all options and logic for spawning commands
type Spawn struct {
	Command         []string
	GenerateKey     bool
	NoProxy         bool
	ValidPrincipals string
	VaultSigningUrl string
}

type ProxyAgent struct {
	Keyring *proxyagent.ProxyKeyring
	Socket  string
}

type KeyPair struct {
	PrivateKey string
	PublicKey  string
	SignedKey  string
}

func (s *Spawn) Run() error {
	fmt.Println("Starting the SSH proxy agent...")

	vars := getCurrentEnv()
	proxyAgent, err := s.startProxyKeyring()
	if err != nil {
		return err
	}
	vars["SSH_AUTH_SOCK"] = proxyAgent.Socket
	defer func() {
		// TODO: look at logging here
		_ = proxyAgent.Keyring.Close()
	}()

	if s.GenerateKey {
		var addedKey *agent.AddedKey
		addedKey, err = s.generateKey()
		if err != nil {
			return err
		}

		err = proxyAgent.Keyring.Add(*addedKey)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command(s.Command[0], s.Command[1:]...)
	cmd.Env = buildEnviron(vars)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return err
	}

	cmdCompletion := make(chan error)
	go func() {
		cmdCompletion <- cmd.Wait()
	}()

	// because we are waiting for our child to exit we can ignore these signals
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case err = <-cmdCompletion:
			return err
		}
	}
}

func (s *Spawn) startProxyKeyring() (*ProxyAgent, error) {
	var upstream_auth_sock string
	if !s.NoProxy {
		upstream_auth_sock = os.Getenv("SSH_AUTH_SOCK")
	}

	if s.VaultSigningUrl != "" {
		if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
			vaultURL, vaultURLErr := url.Parse(vaultAddr)
			signingURL, signingURLErr := url.Parse(s.VaultSigningUrl)

			if vaultURLErr == nil && signingURLErr == nil {
				s.VaultSigningUrl = vaultURL.ResolveReference(signingURL).String()
			}
		}
	}

	keyring, err := proxyagent.NewProxyKeyring(upstream_auth_sock, s.VaultSigningUrl, s.ValidPrincipals)
	if err != nil {
		return nil, err
	}

	sock, err := keyring.Listen()
	if err != nil {
		return nil, err
	}

	go func() {
		// TODO: look at logging here
		_ = keyring.Serve()
	}()

	return &ProxyAgent{
		Keyring: keyring,
		Socket:  sock,
	}, nil
}

func (s *Spawn) generateKey() (*agent.AddedKey, error) {
	fmt.Println("Generating an RSA key...")
	keyPair, err := generateRSAKeyPair()
	if err != nil {
		return nil, err
	}

	parsedKey, err := ssh.ParseRawPrivateKey([]byte(keyPair.PrivateKey))
	if err != nil {
		return nil, err
	}

	return &agent.AddedKey{
		PrivateKey: parsedKey,
		Comment:    "ssh-proxy-agent-generated-key",
	}, nil
}

func getCurrentEnv() map[string]string {
	environ := os.Environ()
	envs := make(map[string]string)
	for _, env := range environ {
		parts := strings.SplitN(env, "=", 2)
		envs[parts[0]] = parts[1]
	}
	return envs
}

func buildEnviron(vars map[string]string) []string {
	environ := []string{}
	for k, v := range vars {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}
	return environ
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
