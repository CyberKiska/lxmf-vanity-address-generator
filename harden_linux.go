package main

import "syscall"

func disableDumpability() error {
	const prSetDumpable = 4
	_, _, err := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	if err != 0 {
		return err
	}
	return nil
}
