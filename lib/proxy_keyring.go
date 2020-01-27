package proxyagent

import (
	"log"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ProxyKeyring struct {
	keyring  agent.ExtendedAgent
	upstream agent.ExtendedAgent
}

func NewProxyKeyring(keyring agent.Agent, upstream agent.ExtendedAgent) *ProxyKeyring {
	return &ProxyKeyring{
		keyring:  keyring.(agent.ExtendedAgent),
		upstream: upstream,
	}
}

// TODO: should we consider closing upstream here as well?
func (pk *ProxyKeyring) Close() {
	closer, ok := pk.keyring.(interface {
		Close()
	})
	if ok {
		closer.Close()
	}
}

func (pk *ProxyKeyring) List() ([]*agent.Key, error) {
	keys, err := pk.keyring.List()
	if err != nil {
		return nil, err
	}

	if pk.upstream != nil {
		ukeys, err := pk.upstream.List()
		if err != nil {
			log.Printf("[ProxyKeyring] Upstream list error: %v", err)
		} else {
			keys = append(keys, ukeys...)
		}
	}

	return keys, nil
}

func (pk *ProxyKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	sig, err := pk.keyring.Sign(key, data)
	if err == nil {
		return sig, nil
	}

	if pk.upstream != nil {
		usig, uerr := pk.upstream.Sign(key, data)
		if uerr == nil {
			return usig, nil
		}
	}

	return nil, err
}

func (pk *ProxyKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sig, err := pk.keyring.SignWithFlags(key, data, flags)
	if err == nil {
		return sig, nil
	}

	if pk.upstream != nil {
		usig, uerr := pk.upstream.SignWithFlags(key, data, flags)
		if uerr == nil {
			return usig, nil
		}
	}

	return nil, err
}

func (pk *ProxyKeyring) Add(key agent.AddedKey) error {
	return pk.keyring.Add(key)
}

func (pk *ProxyKeyring) Remove(key ssh.PublicKey) error {
	err := pk.keyring.Remove(key)

	if pk.upstream != nil {
		uerr := pk.upstream.Remove(key)
		if uerr == nil {
			err = nil
		}
	}

	return err
}

func (pk *ProxyKeyring) RemoveAll() error {
	err := pk.keyring.RemoveAll()

	if pk.upstream != nil {
		uerr := pk.upstream.RemoveAll()
		if err == nil {
			err = uerr
		}
	}

	return err
}

func (pk *ProxyKeyring) Lock(passphrase []byte) error {
	err := pk.keyring.Lock(passphrase)

	if pk.upstream != nil {
		uerr := pk.upstream.Lock(passphrase)
		if err == nil {
			err = uerr
		}
	}

	return err
}

func (pk *ProxyKeyring) Unlock(passphrase []byte) error {
	err := pk.keyring.Unlock(passphrase)

	if pk.upstream != nil {
		uerr := pk.upstream.Unlock(passphrase)
		if err == nil {
			err = uerr
		}
	}

	return err
}

func (pk *ProxyKeyring) Signers() ([]ssh.Signer, error) {
	signers, err := pk.keyring.Signers()
	if err != nil {
		return nil, err
	}

	if pk.upstream != nil {
		usigners, err := pk.upstream.Signers()
		if err != nil {
			log.Printf("[ProxyKeyring] Upstream signers error: %v", err)
		} else {
			signers = append(signers, usigners...)
		}
	}

	return signers, nil
}

func (pk *ProxyKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
