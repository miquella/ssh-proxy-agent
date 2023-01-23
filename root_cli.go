package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/miquella/ssh-proxy-agent/lib/proxyagent"
)

// RootCLI is the root command for the `ssh-proxy-agent` entrypoint
var RootCLI = &cobra.Command{
	Use:   "ssh-proxy-agent",
	Short: "SSH-Proxy-Agent creates an ssh-agent proxy",

	PreRun:       versionPreRun,
	RunE:         shellRunE,
	SilenceUsage: true,
}

var doctor bool
var interactive bool
var version bool

var agentConfig = proxyagent.AgentConfig{}
var shell = proxyagent.Spawn{}

func init() {
	RootCLI.Flags().BoolVarP(&interactive, "shell", "l", false, "spawn an interactive shell")
	RootCLI.Flags().BoolVarP(&doctor, "doctor", "", false, "verify if a spawned session is running correctly")
	RootCLI.Flags().BoolVar(&version, "version", false, "display version of ssh-proxy-agent")

	RootCLI.Flags().BoolVar(&agentConfig.GenerateRSAKey, "generate-key", false, "generate RSA key pair (default: false)")
	RootCLI.Flags().BoolVar(&agentConfig.DisableProxy, "no-proxy", false, "disable forwarding to an upstream agent (default: false)")
	RootCLI.Flags().BoolVar(&agentConfig.ExposeUnsigned, "expose-unsigned", false, "expose both signed and unsigned versions of keys when signing is enabled (default: false)")
	RootCLI.Flags().StringSliceVar(&agentConfig.ValidPrincipals, "valid-principals", []string{proxyagent.DefaultPrincipal()}, "valid principals for Vault key signing")
	RootCLI.Flags().StringVar(&agentConfig.VaultSigningUrl, "vault-signing-url", "", "HashiCorp Vault url to sign SSH keys")
}

func shellRunE(cmd *cobra.Command, args []string) error {
	if doctor {
		proxyagent.Doctor()
		return nil
	}

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

func versionPreRun(*cobra.Command, []string) {
	if !version {
		return
	}

	version := "(devel)"
	vcsRevision := ""
	vcsModified := false

	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		version = buildInfo.Main.Version

		for _, buildSetting := range buildInfo.Settings {
			switch buildSetting.Key {
			case "vcs.revision":
				vcsRevision = buildSetting.Value
			case "vcs.modified":
				vcsModified = buildSetting.Value == "true"
			}
		}
	}

	fmt.Printf("ssh-proxy-agent %s", version)

	if vcsRevision != "" {
		fmt.Printf(" (%s", vcsRevision)
		if vcsModified {
			fmt.Print("-dirty")
		}
		fmt.Print(")")
	}

	fmt.Println()
	os.Exit(0)
}
