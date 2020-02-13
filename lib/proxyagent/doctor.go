package proxyagent

import (
	"fmt"
	"os"
)

func Doctor() {
	proxySock := os.Getenv("SSH_PROXY_AUTH_SOCK")

	fmt.Println(`
Please note that while this process is meant to help with debugging,
if your ssh-proxy-agent is working correctly feel free to disregard
any warnings.`)

	var doctorMessage string
	switch proxySock {
	case "":
		doctorMessage = `
Warning: the ssh-proxy-agent does not appear to be running.
See 'ssh-proxy-agent --help' for details on spawning the process.`
	case os.Getenv("SSH_AUTH_SOCK"):
		doctorMessage = "\n'ssh-proxy-agent' appears to be running correctly."
	default:
		doctorMessage = `
Warning: the SSH_AUTH_SOCK variable in the proxy shell appears to
have diverged from the proxy agent. As a result, you may experience
difficulties interacting with your SSH agent (e.g. adding or listing keys).

You may reset this variable by running the following command inside
of your proxy agent shell:
	export SSH_AUTH_SOCK=` + proxySock
	}

	fmt.Println(doctorMessage)
}
