//go:build unix

package vectorstate

import "syscall"

const noFollow = syscall.O_NOFOLLOW
