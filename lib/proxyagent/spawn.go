package proxyagent

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/agent"
)

// Spawn contains all options and logic for spawning commands
type Spawn struct {
	Agent   agent.Agent
	Command []string
}

func (s *Spawn) Run() error {
	server := NewServer(s.Agent)
	err := server.Start()
	if err != nil {
		return err
	}
	defer func() {
		// TODO: look at logging here
		_ = server.Stop()
	}()

	vars := getCurrentEnv()
	vars["SSH_AUTH_SOCK"] = server.Socket
	// this is only used to verify if the agent is configured correctly
	vars["SSH_PROXY_AUTH_SOCK"] = server.Socket

	cmd := exec.Command(s.Command[0], s.Command[1:]...)
	cmd.Env = buildEnviron(vars)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return err
	}

	cmdCompletion := make(chan error)
	go func() {
		cmdCompletion <- cmd.Wait()
	}()

	// because we are waiting for our child to exit we can ignore these signals
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case err = <-cmdCompletion:
			return err
		}
	}
}

func getCurrentEnv() map[string]string {
	environ := os.Environ()
	envs := make(map[string]string)
	for _, env := range environ {
		parts := strings.SplitN(env, "=", 2)
		envs[parts[0]] = parts[1]
	}
	return envs
}

func buildEnviron(vars map[string]string) []string {
	environ := []string{}
	for k, v := range vars {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}
	return environ
}
