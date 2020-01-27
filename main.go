package main

import (
	"os"
)

func main() {
	if err := SSHProxyAgentCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
