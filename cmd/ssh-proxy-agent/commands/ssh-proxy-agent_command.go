package commands

import (
	"github.com/spf13/cobra"
)

// SSHProxyAgentCommand is the root command for the `ssh-proxy-agent` entrypoint
var SSHProxyAgentCommand = &cobra.Command{
	Use:   "ssh-proxy-agent",
	Short: "SSH-Proxy-Agent creates an ssh-agent proxy",

	SilenceUsage: true,
}

func init() {
	SSHProxyAgentCommand.AddCommand(ShellCommand)
}
