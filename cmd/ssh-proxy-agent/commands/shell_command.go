package commands

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/miquella/ssh-proxy-agent/operations"
)

var shell = operations.Spawn{}
var username string

// ShellCommand is the `ssh-proxy-agent shell` subcommand
var ShellCommand = &cobra.Command{
	Use:   "shell",
	Short: "Invokes a shell with the proxy ssh-agent running",
	Args:  cobra.OnlyValidArgs,

	RunE: shellRunE,
}

func init() {
	ShellCommand.Flags().BoolVar(&shell.GenerateKey, "generate-key", false, "generate RSA key pair (default: false)")
	ShellCommand.Flags().StringVarP(&username, "username", "u", os.Getenv("USER"), "username for key signing")
	ShellCommand.Flags().StringVar(&shell.VaultSigningUrl, "vault-signing-url", "", "HashiCorp Vault url to sign SSH keys")
}

func shellRunE(cmd *cobra.Command, args []string) error {
	shell.Command = loginShellCommand()
	shell.Username = username
	return shell.Run()
}

func loginShellCommand() []string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	return []string{shell, "--login"}
}
