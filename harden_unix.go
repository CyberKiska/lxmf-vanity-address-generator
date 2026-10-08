//go:build unix

package main

import (
	"errors"
	"syscall"
)

// Best effort only: runtime tracebacks, same-user access, swap and snapshots
// remain outside this protection. Called in main, never in the test runner.
func hardenProcess() error {
	var limits syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limits)
	if err == nil {
		limits.Cur = 0
		err = syscall.Setrlimit(syscall.RLIMIT_CORE, &limits)
	}
	return errors.Join(err, disableDumpability())
}
