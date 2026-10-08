package main

import (
	"os"
	"syscall"
	"testing"
)

func TestLinuxDumpabilityIsClearedInChild(t *testing.T) {
	if os.Getenv("LXMF_TEST_HARDENING") != "1" {
		t.Skip("checked only in disposable hardening child")
	}
	if err := hardenProcess(); err != nil {
		t.Fatal(err)
	}
	const prGetDumpable = 3
	value, _, err := syscall.Syscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if err != 0 || value != 0 {
		t.Fatal("dumpability remains enabled")
	}
}
