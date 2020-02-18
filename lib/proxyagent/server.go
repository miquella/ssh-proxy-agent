package proxyagent

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh/agent"
)

type Server struct {
	Agent  agent.Agent
	Socket string

	listener net.Listener
}

func NewServer(agent agent.Agent) *Server {
	// TODO: allow people to pass in socket
	return &Server{
		Agent: agent,
	}
}

func (s *Server) Start() error {
	err := s.listen()
	if err != nil {
		return err
	}

	go func() {
		// TODO: look at logging here
		_ = s.serve()
	}()

	return nil
}

func (s *Server) Stop() error {
	// call Close() on the keyring if it exists
	closer, ok := s.Agent.(interface {
		Close()
	})
	if ok {
		closer.Close()
	}

	if s.listener != nil {
		return s.listener.Close()
	}

	return nil
}

func (s *Server) GetProxyEnvVars() map[string]string {
	return map[string]string{
		"SSH_AUTH_SOCK":       s.Socket,
		"SSH_PROXY_AUTH_SOCK": s.Socket,
	}
}

func (s *Server) listen() error {
	if s.listener != nil {
		return errors.New("Already listening")
	}

	dir, err := ioutil.TempDir("", "proxykeyring")
	if err != nil {
		return err
	}

	err = os.Chmod(dir, 0700)
	if err != nil {
		return err
	}

	listenerPath := filepath.Join(dir, "listener")
	s.listener, err = net.Listen("unix", listenerPath)
	if err != nil {
		return err
	}

	s.Socket = listenerPath
	return os.Chmod(listenerPath, 0600)
}

func (s *Server) serve() error {
	if s.listener == nil {
		return errors.New("Not listening")
	}

	for {
		c, err := s.listener.Accept()
		if err != nil {
			return err
		}

		go func() {
			defer func() {
				// TODO: look at logging here
				_ = c.Close()
			}()

			// TODO: look at logging here
			_ = agent.ServeAgent(s.Agent, c)
		}()
	}
}
