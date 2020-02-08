package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/miquella/ssh-proxy-agent/lib/proxyagent"
)

// RootCLI is the root command for the `ssh-proxy-agent` entrypoint
var RootCLI = &cobra.Command{
	Use:   "ssh-proxy-agent",
	Short: "SSH-Proxy-Agent creates an ssh-agent proxy",

	RunE:         shellRunE,
	SilenceUsage: true,

	Version: "0.3.unstable",
}

var interactive bool

var agentConfig = proxyagent.AgentConfig{}
var shell = proxyagent.Spawn{}

func init() {
	RootCLI.Flags().BoolVarP(&interactive, "shell", "l", false, "spawn an interactive shell")

	RootCLI.Flags().BoolVar(&agentConfig.GenerateRSAKey, "generate-key", false, "generate RSA key pair (default: false)")
	RootCLI.Flags().BoolVar(&agentConfig.DisableProxy, "no-proxy", false, "disable forwarding to an upstream agent (default: false)")
	RootCLI.Flags().StringSliceVar(&agentConfig.ValidPrincipals, "valid-principals", []string{os.Getenv("USER")}, "valid principals for Vault key signing")
	RootCLI.Flags().StringVar(&agentConfig.VaultSigningUrl, "vault-signing-url", "", "HashiCorp Vault url to sign SSH keys")
}

func shellRunE(cmd *cobra.Command, args []string) error {
	if !interactive {
		return cmd.Usage()
	}

	var err error
	shell.Agent, err = proxyagent.SetupAgent(agentConfig)
	if err != nil {
		return err
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
