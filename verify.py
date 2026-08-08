#!/usr/bin/env python3
"""
Verification script to check compatibility between generated identities
and the reference Reticulum implementation.

Features:
- Basic file format verification (size, structure)
- Comparison with address/hash metadata in .txt file if available
- Fail-closed reference verification of private/public/hash/address material

Requirements:
    pip install cryptography rns

Usage:
    python3 verify.py <identity_file>
    python3 verify.py --manual-only <identity_file>

Examples:
    python3 verify.py my_identity                   # Requires RNS; verifies .txt if present
    python3 verify.py --manual-only my_identity     # Structural checks, no compatibility claim
    python3 verify.py path/to/identity_file         # Verify any identity file
    python3 verify.py my_identity > results.txt     # Save output to file
"""

import argparse
import base64
import hashlib
import os
import sys


EXPECTED_RNS_VERSION = "1.4.2"


def load_identity_binary(filepath):
    """Load identity from binary file (64 bytes private key)"""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) != 64:
        raise ValueError(f"Identity file must be 64 bytes (private key), got {len(data)}")

    # Private key format: X25519_priv (32) + Ed25519_seed (32)
    x25519_private = data[0:32]
    ed25519_seed = data[32:64]

    return {
        'x25519_private': x25519_private,
        'ed25519_seed': ed25519_seed,
    }


def compute_lxmf_address(identity):
    """Compute LXMF address from identity (manual calculation matching RNS.Destination.hash)"""
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization

    # Reconstruct public keys from private keys
    x25519_priv_key = x25519.X25519PrivateKey.from_private_bytes(identity['x25519_private'])
    x25519_pub = x25519_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    ed25519_priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(identity['ed25519_seed'])
    ed25519_pub = ed25519_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Build public key: X25519_pub (32) + Ed25519_pub (32) = 64 bytes
    public_key = x25519_pub + ed25519_pub

    # Compute identity hash: SHA-256(public_key)[:16]
    identity_hash = hashlib.sha256(public_key).digest()[:16]

    # Compute name hash: SHA-256("lxmf.delivery")[:10]
    name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]

    # Compute destination hash: SHA-256(name_hash + identity_hash)[:16]
    addr_hash_material = name_hash + identity_hash
    destination_hash = hashlib.sha256(addr_hash_material).digest()[:16]

    return destination_hash, identity_hash, public_key


def verify_with_reticulum(filepath, raw_private):
    """Verify all derived material using the installed Reticulum library."""
    try:
        import RNS
    except ImportError:
        return None

    identity = RNS.Identity.from_file(filepath)
    if identity is None:
        raise ValueError("RNS.Identity.from_file() rejected the identity file")

    probe_message = b"lxmf-vanity RNS 1.4.2 compatibility probe"
    signature = identity.sign(probe_message)
    ciphertext = identity.encrypt(probe_message)

    return {
        "version": getattr(RNS, "__version__", "unknown"),
        "public": identity.get_public_key(),
        "identity_hash": identity.hash,
        "destination_hash": RNS.Destination.hash(identity, "lxmf", "delivery"),
        "name_destination_hash": RNS.Destination.hash_from_name_and_identity(
            "lxmf.delivery", identity
        ),
        "private_roundtrip": identity.get_private_key() == raw_private,
        "signature_roundtrip": identity.validate(signature, probe_message),
        "encryption_roundtrip": identity.decrypt(ciphertext) == probe_message,
    }


def verify_txt_file(manual_address, identity_hash, public_key, raw_private, filepath):
    """Verify address/hash metadata in .txt file if it exists"""
    txt_file = filepath + ".txt"
    if not os.path.exists(txt_file):
        return None

    print(f"\nComparing with {txt_file}...")
    with open(txt_file, 'r') as f:
        content = f.read()

    expected_address = manual_address.hex()
    expected_identity_hash = identity_hash.hex()
    txt_address = None
    txt_identity_hash = None

    for line in content.split('\n'):
        if line.startswith('Address (LXMF):'):
            txt_address = line.split(':', 1)[1].strip()
            print(f"\n{line}")
        elif line.startswith('Identity Hash:'):
            txt_identity_hash = line.split(':', 1)[1].strip()
            print(line)

    address_match = txt_address == expected_address
    identity_match = txt_identity_hash == expected_identity_hash
    expected_specifier = (
        f"<lxmf.delivery.{expected_identity_hash}:{expected_address}>"
    )
    expected_public_lines = [
        f"X25519 Public:  {public_key[:32].hex()}",
        f"Ed25519 Public: {public_key[32:].hex()}",
        f"Combined:       {public_key.hex()}",
    ]
    public_material_match = all(line in content for line in expected_public_lines)
    specifier_match = expected_specifier in content

    private_base64 = base64.urlsafe_b64encode(raw_private).decode("ascii")
    private_base32 = base64.b32encode(raw_private).decode("ascii")
    public_only = "This metadata file contains public information only." in content
    private_warning = "WARNING: Reversible private identity exports follow" in content
    if public_only and not private_warning:
        sensitivity_match = (
            private_base64 not in content and private_base32 not in content
        )
    elif private_warning and not public_only:
        sensitivity_match = (
            private_base64 in content and private_base32 in content
        )
    else:
        sensitivity_match = False

    if address_match:
        print("✓ Address matches")
    else:
        print(f"✗ Address MISMATCH! expected {expected_address}")

    if identity_match:
        print("✓ Identity hash matches")
    else:
        print(f"✗ Identity hash MISMATCH! expected {expected_identity_hash}")

    for label, passed in {
        "public key metadata": public_material_match,
        "full destination specifier": specifier_match,
        "metadata sensitivity label/exports": sensitivity_match,
    }.items():
        print(f"{'✓' if passed else '✗'} {label}")

    return all(
        [
            address_match,
            identity_match,
            public_material_match,
            specifier_match,
            sensitivity_match,
        ]
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Verify a generated identity against Reticulum"
    )
    parser.add_argument("identity_file")
    parser.add_argument(
        "--manual-only",
        action="store_true",
        help="perform structural/manual checks without claiming Reticulum compatibility",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    filepath = args.identity_file

    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        return 1

    print("=== LXMF Identity File Verification ===\n")

    # Read binary file
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File: {filepath}")
    print(f"Size: {len(data)} bytes")

    # Check file size
    if len(data) != 64:
        print(f"\n⚠️  WARNING: Expected 64 bytes (private key), got {len(data)}")
        print("This file may not be compatible with Reticulum!")
        return 1
    else:
        print("✓ Correct size (64 bytes)\n")

    # Load and parse identity
    print(f"Loading identity from: {filepath}")
    identity = load_identity_binary(filepath)

    print("\nIdentity private key: loaded (hidden)")

    # Manual calculation
    try:
        manual_address, identity_hash, public_key = compute_lxmf_address(identity)
    except ImportError as exc:
        print(f"Error: manual cryptographic checks require the cryptography package: {exc}")
        return 2
    print(f"\nDerived public keys:")
    print(f"  X25519 Public:   {public_key[:32].hex()}")
    print(f"  Ed25519 Public:  {public_key[32:].hex()}")
    print(f"\nManual calculation:")
    print(f"  Identity Hash: {identity_hash.hex()}")
    print(f"  LXMF Address:  {manual_address.hex()}")

    # Verify against .txt file if it exists
    txt_verification_result = verify_txt_file(
        manual_address, identity_hash, public_key, data, filepath
    )

    if args.manual_only:
        print("\n⚠ MANUAL-ONLY MODE: no Reticulum compatibility claim was tested.")
        if txt_verification_result is False:
            return 1
        return 0

    print("\nReticulum reference verification:")
    try:
        result = verify_with_reticulum(filepath, data)
    except Exception as exc:
        print(f"  ✗ Reticulum rejected the identity: {exc}")
        return 1

    if result is None:
        print("  ✗ Reticulum is not installed; compatibility was NOT verified.")
        print("    Install the pinned/supported RNS version or use --manual-only explicitly.")
        return 2

    print(f"  RNS Version: {result['version']}")
    print(f"  LXMF Address: {result['destination_hash'].hex()}")

    checks = {
        f"RNS version is exactly {EXPECTED_RNS_VERSION}": (
            result["version"] == EXPECTED_RNS_VERSION
        ),
        "private identity round-trip": result["private_roundtrip"],
        "public key bytes": result["public"] == public_key,
        "identity hash": result["identity_hash"] == identity_hash,
        "Destination.hash": result["destination_hash"] == manual_address,
        "hash_from_name_and_identity": (
            result["name_destination_hash"] == manual_address
        ),
        "signature round-trip": result["signature_roundtrip"],
        "encryption round-trip": result["encryption_roundtrip"],
        "metadata": txt_verification_result is not False,
    }

    failed = [name for name, passed in checks.items() if not passed]
    for name, passed in checks.items():
        print(f"  {'✓' if passed else '✗'} {name}")

    if failed:
        print("\n✗ FAILURE: Reticulum compatibility checks failed: " + ", ".join(failed))
        return 1

    print("\n✓ SUCCESS: Identity bytes and LXMF address match Reticulum.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
