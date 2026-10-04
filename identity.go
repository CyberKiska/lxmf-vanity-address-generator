package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"runtime"
)

const (
	addressHexLength        = 32
	addressByteLength       = addressHexLength / 2
	identityPrivateKeySize  = 64
	attemptFlushInterval    = 1024
	maxWorkerCount          = 256
	base64PrivateExportSize = 88
	base32PrivateExportSize = 104
)

var lxmfNameHash = func() [10]byte {
	full := sha256.Sum256([]byte("lxmf.delivery"))
	var out [10]byte
	copy(out[:], full[:10])
	return out
}()

// Identity contains the Reticulum X25519 encryption and Ed25519 signing keys
// needed to persist a private identity and derive its LXMF delivery address.
type Identity struct {
	X25519Private [32]byte
	X25519Public  [32]byte
	Ed25519Seed   [32]byte
	Ed25519Public [32]byte
	Hash          [16]byte
	Address       [16]byte
}

func newAddressHashMaterial() [26]byte {
	var material [26]byte
	copy(material[:10], lxmfNameHash[:])
	return material
}

func deriveCandidate(identity *Identity, randBuf *[identityPrivateKeySize]byte, publicKey *[64]byte, addrHashMaterial *[26]byte) error {
	copy(identity.X25519Private[:], randBuf[0:32])
	copy(identity.Ed25519Seed[:], randBuf[32:64])

	clampX25519(&identity.X25519Private)
	if err := generateX25519Public(identity); err != nil {
		return fmt.Errorf("X25519 public-key derivation unavailable: %w", err)
	}
	generateEd25519Public(identity)

	copy(publicKey[0:32], identity.X25519Public[:])
	copy(publicKey[32:64], identity.Ed25519Public[:])

	identityHashFull := sha256.Sum256(publicKey[:])
	copy(identity.Hash[:], identityHashFull[:16])
	copy(addrHashMaterial[10:26], identityHashFull[:16])

	addrHashFull := sha256.Sum256(addrHashMaterial[:])
	copy(identity.Address[:], addrHashFull[:16])
	return nil
}

func generateX25519Public(identity *Identity) error {
	privateKey, err := ecdh.X25519().NewPrivateKey(identity.X25519Private[:])
	if err != nil {
		return err
	}
	copy(identity.X25519Public[:], privateKey.PublicKey().Bytes())
	runtime.KeepAlive(privateKey)
	return nil
}

func generateEd25519Public(identity *Identity) {
	privateKey := ed25519.NewKeyFromSeed(identity.Ed25519Seed[:])
	copy(identity.Ed25519Public[:], privateKey[32:])
	wipeBytes(privateKey)
}

func clampX25519(privateKey *[32]byte) {
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
}

func wipeIdentitySecrets(identity *Identity) {
	wipeBytes(identity.X25519Private[:])
	wipeBytes(identity.Ed25519Seed[:])
	runtime.KeepAlive(identity)
}

func wipeBytes(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

func validateIdentityConsistency(identity *Identity) error {
	if identity == nil {
		return fmt.Errorf("identity must not be nil")
	}

	var input [identityPrivateKeySize]byte
	var expected Identity
	var publicKey [64]byte
	material := newAddressHashMaterial()
	defer wipeBytes(input[:])
	defer wipeIdentitySecrets(&expected)
	copy(input[0:32], identity.X25519Private[:])
	copy(input[32:64], identity.Ed25519Seed[:])
	if err := deriveCandidate(&expected, &input, &publicKey, &material); err != nil {
		return err
	}

	valid := 1
	valid &= subtle.ConstantTimeCompare(identity.X25519Private[:], expected.X25519Private[:])
	valid &= subtle.ConstantTimeCompare(identity.Ed25519Seed[:], expected.Ed25519Seed[:])
	valid &= subtle.ConstantTimeCompare(identity.X25519Public[:], expected.X25519Public[:])
	valid &= subtle.ConstantTimeCompare(identity.Ed25519Public[:], expected.Ed25519Public[:])
	valid &= subtle.ConstantTimeCompare(identity.Hash[:], expected.Hash[:])
	valid &= subtle.ConstantTimeCompare(identity.Address[:], expected.Address[:])
	if valid != 1 {
		return fmt.Errorf("identity fields are inconsistent with the private key material; refusing to save")
	}
	return nil
}
