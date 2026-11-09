// Command qpot-sshbackend initializes and audits disposable OpenSSH backends.
package main

import (
	"fmt"
	"os"

	"github.com/qpot/qpot/internal/sshbackend"
)

func main() {
	code := 1
	var err error
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			err = sshbackend.Serve()
			code = 0
		case "record":
			code, err = sshbackend.Record(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
		case "health":
			err = sshbackend.Health()
			code = 0
		default:
			err = fmt.Errorf("unknown session service command")
		}
	} else {
		err = fmt.Errorf("missing session service command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Session service unavailable:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}
