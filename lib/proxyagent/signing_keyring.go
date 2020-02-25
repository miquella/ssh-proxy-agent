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
	comment         string
	expire          *time.Time
	signedPublicKey ssh.PublicKey
	signedUntil     time.Time
	signer          ssh.Signer
}

type signingKeyring struct {
	exitChannel      chan chan bool
	expirationTimer  *time.Timer
	exposeUnsigned   bool
	keys             []signedKey
	locked           bool
	mu               sync.RWMutex
	passphrase       []byte
	signingTimer     *time.Timer
	username         string
	vaultClient      *vault.Client
	vaultSigningPath string
}

var errLocked = errors.New("agent: locked")

func NewSigningKeyring(vaultSigningUrl string, username string, exposeUnsigned bool) (agent.ExtendedAgent, error) {
	host, path, err := parseVaultSigningUrl(vaultSigningUrl)
	if err != nil {
		return nil, err
	}

	vc, err := configureVaultClient(host)
	if err != nil {
		return nil, err
	}

	signingKeyring := &signingKeyring{
		exitChannel:      make(chan chan bool),
		expirationTimer:  time.NewTimer(0),
		exposeUnsigned:   exposeUnsigned,
		signingTimer:     time.NewTimer(0),
		username:         username,
		vaultClient:      vc,
		vaultSigningPath: path,
	}

	go handleExpirationTimers(signingKeyring)

	return signingKeyring, nil
}

func (k *signingKeyring) Close() {
	ackChannel := make(chan bool)
	k.exitChannel <- ackChannel

	// wait for close to complete before ending
	<-ackChannel
}

// expireKeysLocked removes expired keys from the keyring. If a key was added
// with a lifetimesecs contraint and seconds >= lifetimesecs seconds have
// ellapsed, it is removed. The caller *must* be holding the keyring mutex.
func (k *signingKeyring) expireKeysLocked() {
	for _, key := range k.keys {
		if key.expire != nil && time.Now().After(*key.expire) {
			err := k.removeLocked(key.signer.PublicKey().Marshal())
			if err != nil {
				// TODO: write to log, continue
			}
		}
	}
}

// removeLocked does the actual key removal. The caller must already be holding the
// keyring mutex.
func (k *signingKeyring) removeLocked(want []byte) error {
	for i := 0; i < len(k.keys); {
		if bytes.Equal(k.keys[i].signer.PublicKey().Marshal(), want) {
			k.keys = append(k.keys[:i], k.keys[i+1:]...)

			if len(k.keys) == 0 {
				k.stopTimers()
			} else {
				k.renewTimers()
			}

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

	var ids []*agent.Key

	// add signed keys
	for _, key := range k.keys {
		comment := key.comment
		if time.Now().After(key.signedUntil) {
			comment = "[EXPIRED] " + key.comment
		}

		ids = append(ids, &agent.Key{
			Blob:    key.signedPublicKey.Marshal(),
			Comment: comment,
			Format:  key.signedPublicKey.Type(),
		})
	}

	if k.exposeUnsigned {
		// add unsigned keys
		for _, key := range k.keys {
			ids = append(ids, &agent.Key{
				Blob:    key.signer.PublicKey().Marshal(),
				Comment: key.comment,
				Format:  key.signer.PublicKey().Type(),
			})
		}
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
	// TODO: rlock early, unlock during signing, write lock during replace?
	// or are we comfortable leaving this locked for the full duration of a single add?
	signedPublicKey, expiresAt, err := k.signPublicKeyWithVault(pubKey, key.Comment)
	if err != nil {
		return err
	}

	keyToAdd := &signedKey{
		comment:         key.Comment,
		signedPublicKey: signedPublicKey,
		signedUntil:     expiresAt,
		signer:          signer,
	}

	if key.LifetimeSecs > 0 {
		t := time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second)
		keyToAdd.expire = &t
	}

	k.keys = append(k.keys, *keyToAdd)
	k.renewTimers()

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
	k.stopTimers()

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
	k.stopTimers()

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

	// remove any keys that expired during the lock
	k.expireKeysLocked()

	// we do not resign keys when locked, so we need to ensure we resign before we unlock
	keysToRenew := k.getKeysToRenew()
	signedKeys := k.resignKeys(keysToRenew)
	k.updateKeys(signedKeys)

	// enable the timers
	k.renewTimers()

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

	wanted := pubkey.Marshal()
	for _, key := range k.keys {
		if bytes.Equal(key.signedPublicKey.Marshal(), wanted) {
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

	s := make([]ssh.Signer, 0, len(k.keys))
	for _, key := range k.keys {
		s = append(s, key.signer)
	}
	return s, nil
}

// signPublicKeyWithVault signs a public key with a HashiCorp Vault path
func (k *signingKeyring) signPublicKeyWithVault(pubKey ssh.PublicKey, comment string) (ssh.PublicKey, time.Time, error) {
	pubKeyId := &agent.Key{
		Blob:    pubKey.Marshal(),
		Comment: comment,
		Format:  pubKey.Type(),
	}

	ttl := time.Hour
	args := map[string]interface{}{
		"public_key":       pubKeyId.String(),
		"ttl":              ttl.String(),
		"valid_principals": k.username,
	}
	resp, err := k.vaultClient.Logical().Write(k.vaultSigningPath, args)
	if err != nil {
		return nil, time.Time{}, err
	}

	signedCert := resp.Data["signed_key"].(string)
	if signedCert == "" {
		return nil, time.Time{}, fmt.Errorf("Could not get signed cert from Vault")
	}

	signedPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedCert))
	if err != nil {
		return nil, time.Time{}, err
	}

	return signedPublicKey, time.Now().Add(ttl), nil
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

	// confirm that the configured token is valid
	_, err = vc.Auth().Token().LookupSelf()
	if err != nil {
		return nil, fmt.Errorf("Invalid HashiCorp Vault token detected. You may need to run 'vault login' to renew your token.")
	}

	return vc, nil
}

// The keyring does not support any extensions
func (k *signingKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, errors.New("agent: extensions are not supported")
}

// handleRenewalTimer runs as a goroutine to monitor the channels related to key expiration
// and removal and signing expiration and renewal
func handleExpirationTimers(keyring *signingKeyring) {
	for {
		// stop timers if there are no keys or the keyring is locked
		if keyring.locked || len(keyring.keys) == 0 {
			keyring.stopTimers()
		}

		select {
		case <-keyring.expirationTimer.C:
			func() {
				keyring.mu.Lock()
				defer keyring.mu.Unlock()

				// remove all expired keys
				keyring.expireKeysLocked()
			}()

			func() {
				keyring.mu.RLock()
				defer keyring.mu.RUnlock()

				keyring.renewTimers()
			}()
		case <-keyring.signingTimer.C:
			// renew all expired signatures (the mutex is handled internally)
			keyring.renewExpiringCerts()

			func() {
				keyring.mu.RLock()
				defer keyring.mu.RUnlock()

				keyring.renewTimers()
			}()
		case resp := <-keyring.exitChannel:
			resp <- true
			break
		}
	}
}

// stops all timers in the keyring
func (k *signingKeyring) stopTimers() {
	k.expirationTimer.Stop()
	k.signingTimer.Stop()
}

// resetExpirationTimer resets the timer to the next expiring key
// the caller *must* hold at least the read lock
func (k *signingKeyring) renewTimers() {
	k.stopTimers()

	if len(k.keys) == 0 {
		return
	}

	var nextKeyExpiration time.Time // it's possible for there to be no key expiration
	nextSigningExpiration := k.keys[0].signedUntil

	for _, key := range k.keys {
		// get soonest key expiration
		if key.expire != nil && (nextKeyExpiration.IsZero() || (key.expire).Before(nextKeyExpiration)) {
			nextKeyExpiration = *key.expire
		}

		// get soonest signing expiration
		if key.signedUntil.Before(nextSigningExpiration) {
			nextSigningExpiration = key.signedUntil
		}
	}

	// ensure a 5 minute lower bound on signing renewal checks to avoid overhead
	// since we are using a 10 minute buffer window
	signDuration := time.Until(nextSigningExpiration) - time.Minute*10
	if signDuration > time.Minute*5 {
		nextSigningExpiration = time.Now().Add(signDuration)
	}
	nextSigningExpiration = time.Now().Add(time.Minute * 5)

	if nextKeyExpiration.IsZero() {
		k.expirationTimer.Stop()
	} else {
		k.expirationTimer.Reset(time.Until(nextKeyExpiration))
	}

	k.signingTimer.Reset(time.Until(nextSigningExpiration))
}

// getKeysToRenew identifies all public keys whose signing will expire in the next 20 minutes
// this method *must* be wrapped in at least a read lock from the caller
func (k *signingKeyring) getKeysToRenew() []signedKey {
	// we will renew any keys that expire in the next 20 minutes
	renewalTime := time.Now().Add(time.Minute * 20)

	keysToRenew := []signedKey{}
	for _, key := range k.keys {
		if key.signedUntil.Before(renewalTime) {
			keysToRenew = append(keysToRenew, key)
		}
	}

	return keysToRenew
}

// resignKeys takes a list of signed keys and re-signs them with Hashicorp Vault
func (k *signingKeyring) resignKeys(keysToRenew []signedKey) []signedKey {
	resignedKeys := []signedKey{}
	for _, key := range keysToRenew {
		signedPublicKey, expiresAt, err := k.signPublicKeyWithVault(key.signer.PublicKey(), key.comment)
		if err != nil {
			// TODO: log and skip if we fail to sign
		} else {
			resignedKeys = append(resignedKeys, signedKey{
				comment:         key.comment,
				signedPublicKey: signedPublicKey,
				signedUntil:     expiresAt,
				signer:          key.signer,
			})
		}
	}
	return resignedKeys
}

// updateKeys takes a list of signed keys and updates all keys in the keychain that match
// the public key of a given key. Given keys that do not have a match are ignored.
// this *must* be wrapped in a write lock by the caller
func (k *signingKeyring) updateKeys(newKeys []signedKey) {
	for _, newKey := range newKeys {
		for i, currentKey := range k.keys {
			if bytes.Equal(currentKey.signer.PublicKey().Marshal(), newKey.signer.PublicKey().Marshal()) {
				k.keys[i].signedPublicKey = newKey.signedPublicKey
				k.keys[i].signedUntil = newKey.signedUntil
				break
			}
		}
	}
}

// renewExpiringCerts identifies, signs, and updates all keys that will expire
// in the next 20 minutes.
func (k *signingKeyring) renewExpiringCerts() {
	keysToRenew := []signedKey{}
	func() {
		k.mu.RLock()
		defer k.mu.RUnlock()

		keysToRenew = k.getKeysToRenew()
	}()

	signedKeys := k.resignKeys(keysToRenew)

	func() {
		k.mu.Lock()
		defer k.mu.Unlock()

		k.updateKeys(signedKeys)
	}()
}
