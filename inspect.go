package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

func inspectIdentity(path string, identity *Identity) (unmasked bool, err error) {
	target, err := openOutputTarget(path)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, target.root.Close()) }()
	entry, err := target.root.Lstat(target.name)
	if err != nil {
		return false, err
	}
	if !entry.Mode().IsRegular() {
		return false, fmt.Errorf("inspection input must be a regular file")
	}
	file, err := target.root.OpenFile(target.name, safeReadFlags, 0)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(entry, info) || info.Size() != identityPrivateKeySize {
		return false, fmt.Errorf("inspection input must be a regular file of exactly 64 bytes")
	}
	var raw [65]byte
	defer wipeBytes(raw[:])
	n, readErr := io.ReadFull(file, raw[:])
	if n != 64 || (readErr != io.EOF && readErr != io.ErrUnexpectedEOF) {
		return false, fmt.Errorf("inspection input must contain exactly 64 bytes")
	}
	var input [64]byte
	copy(input[:], raw[:64])
	defer wipeBytes(input[:])
	var public [64]byte
	material := newAddressHashMaterial()
	if err := deriveCandidate(identity, &input, &public, &material); err != nil {
		return false, err
	}
	unmasked = !bytes.Equal(identity.X25519Private[:], raw[:32])
	// Preserve the original imported encoding; inspection never writes it.
	copy(identity.X25519Private[:], raw[:32])
	return unmasked, nil
}
