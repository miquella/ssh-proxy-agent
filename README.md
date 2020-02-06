# ssh-proxy-agent

An SSH agent capable of proxying requests and signing keys via [HashiCorp Vault].

When working with sensitive SSH keys (e.g. keys for production infrastructure) it can be desirable
to separate them from other keys. With `ssh-proxy-agent`, keys can be isolated to a particular
environment will still allowing access to the outer environment's keys.

Signing keys via HashiCorp Vault is also supported and works well when combined with on-the-fly key
generation.

[HashiCorp Vault]: https://github.com/hashicorp/vault

## Installation

### Manual

As long as you have a proper Go environment set up you should be able to install using `go get`:

```console
go get -u github.com/miquella/ssh-proxy-agent/cmd/...
```

## Getting Started

`ssh-proxy-agent` can act as a standalone agent or can proxy requests to an upstream agent. To
get started, the basic invocation to spawn an agent is:

```console
$ ssh-proxy-agent --shell
```

This will spawn an interactive shell with the new SSH agent. If you have an existing agent
configured in your `SSH_AUTH_SOCK` env var the new agent will proxy requests to it and any
keys in your upstream agent will be available in the proxy agent. Any keys added to the proxy
agent will be isolated from the upstream agent and will only remain available while the shell
is active.

Take note that because `ssh-proxy-agent` uses the `SSH_AUTH_SOCK` env var to configure the new
agent, you will need to ensure this variable does not get overrode when opening a new shell
(e.g. through a .bashrc or similar file).

If you wish to run the proxy agent more securely, you can disable proxying to an upstream agent
via:

```console
$ ssh-proxy-agent --shell --no-proxy
```

## Key Signing

If you have access to a HashiCorp Vault instance that is configured for SSH key signing, you can
configure the proxy agent to automatically sign all keys added to the agent:

```console
$ ssh-proxy-agent --shell --vault-signing-url https://vault.address.com/key/signing/path
```

If the `VAULT_ADDR` environment variable is set you can provide a relative path to the
`--vault-signing-url` instead of the full address. For example:
`--vault-signing-url key/signing/path`.

All keys added to the agent will be signed for a one hour duration and will be automatically
renewed prior to expiration to ensure that the keys are always valid.

You must have a Vault token configured for this work, either via the `VAULT_TOKEN` environment
variable or a `.vault-token` file located in your home directory.

This is particularly useful when combined with `--generate-key` which will generate an in-memory
key to seed the agent that can be signed on creation.

```console
$ ssh-proxy-agent --shell --vault-signing-url https://vault.address.com/key/signing/path
--generate-key
```

## More Details

To explore the other flag options and see usage rules you can access the help menu with:

```console
$ ssh-proxy-agent --help
```
