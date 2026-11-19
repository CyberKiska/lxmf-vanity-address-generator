//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestHardeningRunsOnlyInDisposableProcess(t *testing.T) {
	if os.Getenv("LXMF_TEST_HARDENING") == "1" {
		if err := hardenProcess(); err != nil {
			t.Fatal(err)
		}
		var limits syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limits); err != nil || limits.Cur != 0 {
			t.Fatal("core limit not cleared")
		}
		return
	}
	var before, after syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^Test(HardeningRunsOnlyInDisposableProcess|LinuxDumpabilityIsClearedInChild)$")
	cmd.Env = append(os.Environ(), "LXMF_TEST_HARDENING=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hardening child: %v: %s", err, out)
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &after); err != nil || before != after {
		t.Fatal("test runner core limit changed")
	}
}
