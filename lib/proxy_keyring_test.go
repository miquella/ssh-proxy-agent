package proxyagent_test

import (
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/miquella/ssh-proxy-agent/lib"
)

func TestProxyKeyring(t *testing.T) {
	keyring, err := proxyagent.NewProxyKeyring("")
	if err != nil {
		t.Fatalf("Failed to instantiate ProxyKeyring: %v", err)
	}

	var ikeyring interface{} = keyring
	if _, ok := ikeyring.(agent.Agent); !ok {
		t.Errorf("ProxyKeyring doesn't comply with agent.Agent interface")
	}

	if _, ok := ikeyring.(agent.ExtendedAgent); !ok {
		t.Errorf("ProxyKeyring doesn't comply with agent.ExtendedAgent interface")
	}
}
