package main

import (
	"os"

	"github.com/miquella/ssh-proxy-agent/cmd/ssh-proxy-agent/commands"
)

func main() {
	if err := commands.SSHProxyAgentCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
