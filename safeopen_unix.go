//go:build unix

package main

import (
	"os"
	"syscall"
)

// Nonblocking open prevents a substituted FIFO from hanging before Stat.
const safeReadFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
