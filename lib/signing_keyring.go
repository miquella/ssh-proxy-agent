package proxyagent

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/miquella/ssh-proxy-agent/credentials"
)

type signedKey struct {
	comment   string
	expire    *time.Time
	signedKey ssh.PublicKey
	signer    ssh.Signer
}

type signingKeyring struct {
	keys             []signedKey
	locked           bool
	mu               sync.RWMutex
	passphrase       []byte
	username         string
	vaultClient      *vault.Client
	vaultSigningPath string
}

var errLocked = errors.New("agent: locked")

func NewSigningKeyring(vaultSigningUrl string, username string) (agent.ExtendedAgent, error) {
	host, path, err := parseVaultSigningUrl(vaultSigningUrl)
	if err != nil {
		return nil, err
	}

	vc, err := configureVaultClient(host)
	if err != nil {
		return nil, err
	}

	return &signingKeyring{
		username:         username,
		vaultClient:      vc,
		vaultSigningPath: path,
	}, nil
}

// expireKeysLocked removes expired keys from the keyring. If a key was added
// with a lifetimesecs contraint and seconds >= lifetimesecs seconds have
// ellapsed, it is removed. The caller *must* be holding the keyring mutex.
func (k *signingKeyring) expireKeysLocked() {
	// TODO: handle Vault-signed key expiration / renewal
	for _, key := range k.keys {
		if key.expire != nil && time.Now().After(*key.expire) {
			k.removeLocked(key.signer.PublicKey().Marshal())
		}
	}
}

// removeLocked does the actual key removal. The caller must already be holding the
// keyring mutex.
func (k *signingKeyring) removeLocked(want []byte) error {
	for i := 0; i < len(k.keys); {
		if bytes.Equal(k.keys[i].signer.PublicKey().Marshal(), want) {
			k.keys = append(k.keys[:i], k.keys[i+1:]...)
			return nil
		} else {
			i++
		}
	}

	return errors.New("agent: key not found")
}

// List returns the identities known to the agent.
func (k *signingKeyring) List() ([]*agent.Key, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	k.expireKeysLocked()
	var ids []*agent.Key
	for _, key := range k.keys {
		ids = append(ids, &agent.Key{
			Blob:    key.signedKey.Marshal(),
			Comment: key.comment,
			Format:  key.signedKey.Type(),
		})
	}
	return ids, nil
}

// Adds a private key to the keyring. If a certificate
// is given, that certificate is added as public key. Note that
// any constraints given are ignored.
func (k *signingKeyring) Add(key agent.AddedKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.locked {
		return errLocked
	}

	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}

	pubKey := signer.PublicKey()
	id := &agent.Key{
		Blob:    pubKey.Marshal(),
		Comment: key.Comment,
		Format:  pubKey.Type(),
	}

	signedKeyString, err := k.SignKeyWithVault(id.String())
	if err != nil {
		return err
	}

	signedPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKeyString))
	if err != nil {
		return err
	}

	signedKey := signedKey{
		comment:   key.Comment,
		signedKey: signedPublicKey,
		signer:    signer,
	}

	if key.LifetimeSecs > 0 {
		t := time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second)
		signedKey.expire = &t
	}

	k.keys = append(k.keys, signedKey)
	return nil
}

// Remove removes all identities with the given public key.
func (k *signingKeyring) Remove(key ssh.PublicKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.locked {
		return errLocked
	}

	return k.removeLocked(key.Marshal())
}

// RemoveAll removes all identities.
func (k *signingKeyring) RemoveAll() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.locked {
		return errLocked
	}

	k.keys = nil
	return nil
}

// Lock locks the agent. Sign and Remove will fail, and List will return an empty list.
func (k *signingKeyring) Lock(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.locked {
		return errLocked
	}

	k.locked = true
	k.passphrase = passphrase
	return nil
}

// Unlock undoes the effect of Lock.
func (k *signingKeyring) Unlock(passphrase []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.locked {
		return errors.New("agent: not locked")
	}

	if 1 != subtle.ConstantTimeCompare(passphrase, k.passphrase) {
		return fmt.Errorf("agent: incorrect passphrase")
	}

	k.locked = false
	k.passphrase = nil
	return nil
}

// Sign returns a signature for the data.
func (k *signingKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return k.SignWithFlags(key, data, 0)
}

func (k *signingKeyring) SignWithFlags(pubkey ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.locked {
		return nil, errLocked
	}

	k.expireKeysLocked()
	wanted := pubkey.Marshal()
	for _, key := range k.keys {
		if bytes.Equal(key.signedKey.Marshal(), wanted) {
			if flags == 0 {
				return key.signer.Sign(rand.Reader, data)
			} else {
				if algorithmSigner, ok := key.signer.(ssh.AlgorithmSigner); !ok {
					return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", key.signer)
				} else {
					var algorithm string
					switch flags {
					case agent.SignatureFlagRsaSha256:
						algorithm = ssh.SigAlgoRSASHA2256
					case agent.SignatureFlagRsaSha512:
						algorithm = ssh.SigAlgoRSASHA2512
					default:
						return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
					}
					return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				}
			}
		}
	}
	return nil, errors.New("not found")
}

// Signers returns signers for all the known keys.
func (k *signingKeyring) Signers() ([]ssh.Signer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.locked {
		return nil, errLocked
	}

	k.expireKeysLocked()
	s := make([]ssh.Signer, 0, len(k.keys))
	for _, key := range k.keys {
		s = append(s, key.signer)
	}
	return s, nil
}

// SignKeyWithVault signs a public key with a HashiCorp Vault path
func (k *signingKeyring) SignKeyWithVault(pubKey string) (string, error) {
	args := map[string]interface{}{
		"public_key":       string(pubKey),
		"ttl":              (16 * time.Hour).String(), // TODO: be more decisive about this
		"valid_principals": k.username,
	}
	resp, err := k.vaultClient.Logical().Write(k.vaultSigningPath, args)
	if err != nil {
		return "", err
	}

	signedCert := resp.Data["signed_key"].(string)
	if signedCert == "" {
		return "", fmt.Errorf("Could not get signed cert from Vault")
	}

	return signedCert, nil
}

func parseVaultSigningUrl(signingUrl string) (string, string, error) {
	parsedUrl, err := url.Parse(signingUrl)
	if err != nil {
		return "", "", err
	}

	signingHost := parsedUrl.Scheme + "://" + parsedUrl.Host
	return signingHost, parsedUrl.Path, nil
}

func configureVaultClient(signingHost string) (*vault.Client, error) {
	vc, err := vault.NewClient(&vault.Config{Address: signingHost})
	if err != nil {
		return nil, err
	}

	token, err := credentials.GetVaultToken()
	if err != nil {
		return nil, err
	}

	vc.SetToken(token)
	return vc, nil
}

// The keyring does not support any extensions
func (k *signingKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, errors.New("agent: extensions are not supported")
}
