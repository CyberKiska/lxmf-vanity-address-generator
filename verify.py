#!/usr/bin/env python3
"""
Verification script to check compatibility between generated identities
and the reference Reticulum implementation.

Features:
- Basic file format verification (size, structure)
- Comparison with .txt file if available
- Full cryptographic verification with Reticulum compatibility check

Requirements:
    pip install cryptography rns

Usage:
    python3 verify.py <identity_file>

Examples:
    python3 verify.py my_identity                   # Verify with .txt file if exists
    python3 verify.py path/to/identity_file         # Verify any identity file
    python3 verify.py my_identity > results.txt     # Save output to file
"""

import sys
import os
import hashlib

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

def verify_with_reticulum(filepath):
    """Verify using actual Reticulum library (if available)"""
    try:
        import RNS

        # Load identity using Reticulum
        identity = RNS.Identity.from_file(filepath)

        # Compute LXMF destination hash using static method
        # This avoids transport initialization issues
        reticulum_hash = RNS.Destination.hash(identity, "lxmf", "delivery")

        return reticulum_hash
    except ImportError:
        return None

def verify_txt_file(identity_data, filepath):
    """Verify identity data against .txt file if it exists"""
    txt_file = filepath + ".txt"
    if not os.path.exists(txt_file):
        return None

    print(f"\nComparing with {txt_file}...")
    with open(txt_file, 'r') as f:
        content = f.read()

    # Check if private keys match
    x25519_priv = identity_data['x25519_private']
    ed25519_seed = identity_data['ed25519_seed']

    x25519_match = x25519_priv.hex() in content
    ed25519_match = ed25519_seed.hex() in content

    if x25519_match:
        print("✓ X25519 private key matches")
    else:
        print("✗ X25519 private key MISMATCH!")

    if ed25519_match:
        print("✓ Ed25519 seed matches")
    else:
        print("✗ Ed25519 seed MISMATCH!")

    # Show address from txt file
    for line in content.split('\n'):
        if line.startswith('Address (LXMF):'):
            print(f"\n{line}")
        elif line.startswith('Identity Hash:'):
            print(line)

    return x25519_match and ed25519_match

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 verify.py <identity_file>")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)

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
        sys.exit(1)
    else:
        print("✓ Correct size (64 bytes)\n")

    # Load and parse identity
    print(f"Loading identity from: {filepath}")
    identity = load_identity_binary(filepath)

    print("\nIdentity private key:")
    print(f"  X25519 Private:  {identity['x25519_private'].hex()}")
    print(f"  Ed25519 Seed:    {identity['ed25519_seed'].hex()}")

    # Verify against .txt file if it exists
    txt_verification_result = verify_txt_file(identity, filepath)

    # Manual calculation
    manual_address, identity_hash, public_key = compute_lxmf_address(identity)
    print(f"\nDerived public keys:")
    print(f"  X25519 Public:   {public_key[:32].hex()}")
    print(f"  Ed25519 Public:  {public_key[32:].hex()}")
    print(f"\nManual calculation:")
    print(f"  Identity Hash: {identity_hash.hex()}")
    print(f"  LXMF Address:  {manual_address.hex()}")

    # Try with Reticulum library
    print(f"\nReticulum library verification:")
    reticulum_hash = verify_with_reticulum(filepath)

    if reticulum_hash is not None:
        print(f"  LXMF Address: {reticulum_hash.hex()}")

        if manual_address == reticulum_hash:
            print("\n✓ SUCCESS: Addresses match! Implementation is compatible.")

            if txt_verification_result is not None:
                if txt_verification_result:
                    print("✓ .txt file verification also passed.")
                else:
                    print("✗ Warning: .txt file verification failed!")

            return 0
        else:
            print("\n✗ FAILURE: Addresses DO NOT match!")
            print(f"  Expected: {reticulum_hash.hex()}")
            print(f"  Got:      {manual_address.hex()}")
            return 1
    else:
        print("  Reticulum library not available (install with: pip install rns)")
        print("  Cannot perform full verification, but manual calculation shown above.")

        if txt_verification_result is not None:
            if txt_verification_result:
                print("✓ .txt file verification passed.")
            else:
                print("✗ .txt file verification failed!")

        return 0

if __name__ == '__main__':
    sys.exit(main())
