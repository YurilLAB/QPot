// Command qpot-sshbackend initializes a disposable OpenSSH backend, then
// replaces itself with sshd.
package main

import (
	"fmt"
	"os"

	"github.com/qpot/qpot/internal/sshbackend"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "Session service unavailable: unknown command")
		os.Exit(2)
	}
	if err := sshbackend.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "Session service unavailable:", err)
		os.Exit(1)
	}
}
