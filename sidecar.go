package main

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
)

func writePublicIdentityInfo(writer io.Writer, identity *Identity, filename string) {
	var publicKey [64]byte
	copy(publicKey[0:32], identity.X25519Public[:])
	copy(publicKey[32:64], identity.Ed25519Public[:])

	fmt.Fprintln(writer, "LXMF Vanity Address Identity")
	fmt.Fprintln(writer, "============================")
	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "Address (LXMF): %s\n", hex.EncodeToString(identity.Address[:]))
	fmt.Fprintf(writer, "Identity Hash:  %s\n", hex.EncodeToString(identity.Hash[:]))
	fmt.Fprintf(writer, "Full Specifier: <lxmf.delivery.%s:%s>\n\n",
		hex.EncodeToString(identity.Hash[:]),
		hex.EncodeToString(identity.Address[:]),
	)
	fmt.Fprintln(writer, "Public Key (X25519 + Ed25519):")
	fmt.Fprintf(writer, "  X25519 Public:  %s\n", hex.EncodeToString(identity.X25519Public[:]))
	fmt.Fprintf(writer, "  Ed25519 Public: %s\n", hex.EncodeToString(identity.Ed25519Public[:]))
	fmt.Fprintf(writer, "  Combined:       %s\n\n", hex.EncodeToString(publicKey[:]))
	fmt.Fprintf(writer, "Private identity file: %q\n", filepath.Base(filename))

}

func (o *outputTarget) writeIdentityInfo(identity *Identity, privateExports bool) error {
	var info bytes.Buffer
	info.Grow(1280)
	writePublicIdentityInfo(&info, identity, o.name)
	if !privateExports {
		fmt.Fprintln(&info, "This metadata file contains public information only.")
	}

	if privateExports {
		// Reserve enough additional capacity before private encodings enter the
		// buffer, so a later growth cannot leave an abandoned secret-bearing copy.
		info.Grow(512)
		var privateKey [identityPrivateKeySize]byte
		var encodedBase64 [base64PrivateExportSize]byte
		var encodedBase32 [base32PrivateExportSize]byte
		defer wipeBytes(privateKey[:])
		defer wipeBytes(encodedBase64[:])
		defer wipeBytes(encodedBase32[:])

		copy(privateKey[0:32], identity.X25519Private[:])
		copy(privateKey[32:64], identity.Ed25519Seed[:])
		base64.URLEncoding.Encode(encodedBase64[:], privateKey[:])
		base32.StdEncoding.Encode(encodedBase32[:], privateKey[:])

		fmt.Fprintln(&info)
		fmt.Fprintln(&info, "WARNING: Reversible private identity exports follow. Protect this file like the identity file.")
		fmt.Fprintln(&info, "Reticulum URL-safe Base64 private identity:")
		info.WriteString("  ")
		info.Write(encodedBase64[:])
		info.WriteByte('\n')
		fmt.Fprintln(&info, "Reticulum Base32 private identity:")
		info.WriteString("  ")
		info.Write(encodedBase32[:])
		info.WriteByte('\n')
	}

	fmt.Fprintln(&info)
	fmt.Fprintln(&info, "Verify with:")
	fmt.Fprintln(&info, "  rnid -i <identity_file> -H lxmf.delivery")

	if privateExports {
		defer wipeBytes(info.Bytes())
	}
	return o.writeFile(o.name+".txt", info.Bytes(), 0o600, false)
}

// outputTarget holds the directory open from preflight through publication. All
// filesystem mutations use relative names within this root, including cleanup.
// The directory must still be trusted: a root does not remove another user's
// permission to alter its entries.
