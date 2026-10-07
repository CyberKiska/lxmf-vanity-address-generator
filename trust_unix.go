//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

func unixDirectoryPolicy(uid uint32, mode os.FileMode, euid uint32) (warning string, err error) {
	if uid != euid && uid != 0 {
		return "", fmt.Errorf("directory owner is neither the effective user nor root")
	}
	if mode.Perm()&0022 != 0 {
		if mode&os.ModeSticky == 0 {
			return "", fmt.Errorf("directory is group/other writable without sticky-entry protection")
		}
		return "sticky shared directory: its owner can alter entries; use a private directory", nil
	}
	return "", nil
}
func directoryProtection(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("directory ownership is unavailable")
	}
	return unixDirectoryPolicy(stat.Uid, info.Mode(), uint32(os.Geteuid()))
}
func fileProtection(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("file ownership is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private file is not owned by the effective user")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fmt.Errorf("private file must be regular with mode 0600")
	}
	return nil
}
