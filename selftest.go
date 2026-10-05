package main

import (
	"encoding/hex"
	"fmt"
)

// PUBLIC TEST VECTOR, never use as an identity.
const (
	goldenX25519Private = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f"
	goldenX25519Public  = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
	goldenEd25519Seed   = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	goldenEd25519Public = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
	goldenIdentityHash  = "aca31af0441d81dbec71e82da0b4b5f5"
	goldenLXMFAddress   = "fae321c442e3c9bdcd7a3e79d850e03c"
)

func knownAnswerIdentity() *Identity {
	expected := new(Identity)
	for _, field := range []struct {
		dst []byte
		src string
	}{
		{expected.X25519Private[:], goldenX25519Private},
		{expected.X25519Public[:], goldenX25519Public},
		{expected.Ed25519Seed[:], goldenEd25519Seed},
		{expected.Ed25519Public[:], goldenEd25519Public},
		{expected.Hash[:], goldenIdentityHash},
		{expected.Address[:], goldenLXMFAddress},
	} {
		if _, err := hex.Decode(field.dst, []byte(field.src)); err != nil {
			panic("invalid compiled public test vector")
		}
	}
	return expected
}

func selfTest(expected *Identity) error {
	var raw [identityPrivateKeySize]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	var actual Identity
	var public [64]byte
	material := newAddressHashMaterial()
	defer wipeBytes(raw[:])
	defer wipeIdentitySecrets(&actual)
	if err := deriveCandidate(&actual, &raw, &public, &material); err != nil {
		return fmt.Errorf("self-test failed: %w", err)
	}
	if expected == nil || actual != *expected {
		return fmt.Errorf("self-test failed: known-answer mismatch")
	}
	return nil
}
