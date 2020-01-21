package commands

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/miquella/ssh-proxy-agent/operations"
)

// SSHProxyAgentCommand is the root command for the `ssh-proxy-agent` entrypoint
var SSHProxyAgentCommand = &cobra.Command{
	Use:   "ssh-proxy-agent",
	Short: "SSH-Proxy-Agent creates an ssh-agent proxy",

	RunE:         shellRunE,
	SilenceUsage: true,

	Version: "0.1.unstable",
}

var interactive bool
var shell = operations.Spawn{}
var validPrincipals []string

func init() {
	SSHProxyAgentCommand.Flags().BoolVarP(&interactive, "shell", "l", false, "spawn an interactive shell")

	SSHProxyAgentCommand.Flags().BoolVar(&shell.NoProxy, "no-proxy", false, "disable forwarding to an upstream agent (default: false)")
	SSHProxyAgentCommand.Flags().BoolVar(&shell.GenerateKey, "generate-key", false, "generate RSA key pair (default: false)")
	SSHProxyAgentCommand.Flags().StringSliceVar(&validPrincipals, "valid-principals", []string{os.Getenv("USER")}, "valid principals for Vault key signing")
	SSHProxyAgentCommand.Flags().StringVar(&shell.VaultSigningUrl, "vault-signing-url", "", "HashiCorp Vault url to sign SSH keys")
}

func shellRunE(cmd *cobra.Command, args []string) error {
	if interactive {
		shell.Command = loginShellCommand()
		shell.ValidPrincipals = strings.Join(validPrincipals, ",")
		return shell.Run()
	} else {
		return cmd.Usage()
	}
}

func loginShellCommand() []string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	return []string{shell, "--login"}
}
