//go:build !unix

package main

import (
	"fmt"
	"os"
)

func directoryProtection(os.FileInfo) (string, error) {
	return "", fmt.Errorf("access-control verification is unavailable; inherited Windows ACLs must already be restricted")
}
func fileProtection(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("private output is not a regular file")
	}
	return fmt.Errorf("private-file ACL verification is unavailable")
}
