package main

import (
	"os"
)

func main() {
	if err := RootCLI.Execute(); err != nil {
		os.Exit(1)
	}
}
