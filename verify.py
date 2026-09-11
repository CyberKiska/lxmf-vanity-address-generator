#!/usr/bin/env python3
"""Verify a 64-byte private identity against the installed Reticulum reference.

Install cryptography and rns. Use --expect-rns-version for an optional CI pin;
--manual-only explicitly omits reference verification. Python is never needed
by the Go search executable.
"""

import argparse
import base64
import hashlib
import importlib.util
import os
import stat
import sys


PRIVATE_SIZE = 64
MAX_METADATA_SIZE = 64 * 1024
PUBLIC_LABEL = "This metadata file contains public information only."
PRIVATE_WARNING = "WARNING: Reversible private identity exports follow. Protect this file like the identity file."
BASE64_LABEL = "Reticulum URL-safe Base64 private identity"
BASE32_LABEL = "Reticulum Base32 private identity"


def read_limited_file(filepath, limit):
    """Read only a bounded regular file; do not block opening Unix FIFOs."""
    fd = os.open(filepath, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("input must be a regular file")
        if info.st_size > limit:
            raise ValueError(f"input exceeds the {limit}-byte size limit")
        data = file.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"input exceeds the {limit}-byte size limit")
        return data


def load_identity_binary(filepath):
    data = read_limited_file(filepath, PRIVATE_SIZE)
    if len(data) != PRIVATE_SIZE:
        raise ValueError(f"identity must be exactly {PRIVATE_SIZE} bytes, got {len(data)}")
    return {"x25519_private": data[:32], "ed25519_seed": data[32:]}


def compute_lxmf_address(identity):
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization

    x_key = x25519.X25519PrivateKey.from_private_bytes(identity["x25519_private"])
    e_key = ed25519.Ed25519PrivateKey.from_private_bytes(identity["ed25519_seed"])
    public = b"".join(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for key in (x_key, e_key)
    )
    identity_hash = hashlib.sha256(public).digest()[:16]
    name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]
    return hashlib.sha256(name_hash + identity_hash).digest()[:16], identity_hash, public


def load_reticulum(provider="auto"):
    if provider == "internal":
        # RNS chooses its provider at import time using find_spec. Temporarily
        # hide PyCA from that discovery, without changing any reference crypto.
        from unittest.mock import patch
        find_spec = importlib.util.find_spec
        with patch("importlib.util.find_spec", side_effect=lambda name, *a, **kw: None if name == "cryptography" else find_spec(name, *a, **kw)):
            import RNS
    else:
        import RNS
    backend = RNS.Cryptography.backend()
    if provider == "internal" and backend != "internal":
        raise ValueError("RNS was already loaded with a different provider; start a fresh process")
    if provider == "pyca" and "PyCA" not in backend:
        raise ValueError("the requested RNS PyCA provider is unavailable")
    return RNS


def verify_with_reticulum(raw_private, provider="auto"):
    try:
        RNS = load_reticulum(provider)
    except ModuleNotFoundError as exc:
        if exc.name == "RNS":
            return None
        raise
    # Use the already bounded snapshot, avoiding a second, unbounded path read.
    # Actual from_file interoperability is additionally tested by the CLI oracle.
    identity = RNS.Identity.from_bytes(raw_private)
    if identity is None:
        raise ValueError("RNS.Identity.from_bytes() rejected the private identity")
    message = b"lxmf-vanity compatibility probe"
    signature = identity.sign(message)
    public_identity = RNS.Identity(create_keys=False)
    public_identity.load_public_key(identity.get_public_key())
    return {
        "version": getattr(RNS, "__version__", "unknown"),
        "provider": RNS.Cryptography.backend(),
        "source": RNS.__file__,
        "public": identity.get_public_key(),
        "identity_hash": identity.hash,
        "destination_hash": RNS.Destination.hash(identity, "lxmf", "delivery"),
        "name_destination_hash": RNS.Destination.hash_from_name_and_identity("lxmf.delivery", identity),
        "private_roundtrip": identity.get_private_key() == raw_private,
        "signature_roundtrip": public_identity.validate(signature, message),
        "encryption_roundtrip": identity.decrypt(public_identity.encrypt(message)) == message,
    }


def parse_metadata(content):
    fields = {}
    labels = {"Address (LXMF)", "Identity Hash", "Full Specifier", "X25519 Public", "Ed25519 Public", "Combined", BASE64_LABEL, BASE32_LABEL}
    lines = [line.strip() for line in content.splitlines()]
    for i, line in enumerate(lines):
        label, separator, value = line.partition(":")
        if not separator or label not in labels:
            continue
        if label in fields:
            raise ValueError(f"duplicate metadata field: {label}")
        if label in (BASE64_LABEL, BASE32_LABEL):
            if value.strip() or i + 1 == len(lines):
                raise ValueError("invalid private export field")
            value = lines[i + 1]
        fields[label] = value.strip()
    return fields, lines


def verify_txt_file(manual_address, identity_hash, public_key, raw_private, filepath):
    txt_file = filepath + ".txt"
    try:
        content = read_limited_file(txt_file, MAX_METADATA_SIZE).decode("utf-8")
    except FileNotFoundError:
        if os.path.lexists(txt_file):
            raise ValueError("metadata is a dangling symlink")
        return None
    try:
        fields, lines = parse_metadata(content)
        expected = {
            "Address (LXMF)": manual_address.hex(),
            "Identity Hash": identity_hash.hex(),
            "Full Specifier": f"<lxmf.delivery.{identity_hash.hex()}:{manual_address.hex()}>",
            "X25519 Public": public_key[:32].hex(),
            "Ed25519 Public": public_key[32:].hex(),
            "Combined": public_key.hex(),
        }
        checks = {label: fields.get(label) == value for label, value in expected.items()}
        private_base64 = base64.urlsafe_b64encode(raw_private).decode("ascii")
        private_base32 = base64.b32encode(raw_private).decode("ascii")
        public_only = lines.count(PUBLIC_LABEL) == 1 and lines.count(PRIVATE_WARNING) == 0
        private_exports = lines.count(PRIVATE_WARNING) == 1 and lines.count(PUBLIC_LABEL) == 0
        if public_only:
            sensitivity = (
                BASE64_LABEL not in fields and BASE32_LABEL not in fields
                and all(value not in content for value in (private_base64, private_base32, raw_private.hex()))
            )
        elif private_exports:
            encoded64 = fields.get(BASE64_LABEL, "")
            encoded32 = fields.get(BASE32_LABEL, "")
            sensitivity = (
                encoded64 == private_base64 and encoded32 == private_base32
                and base64.b64decode(encoded64, altchars=b"-_", validate=True) == raw_private
                and base64.b32decode(encoded32) == raw_private
            )
        else:
            sensitivity = False
        checks["metadata sensitivity label/exports"] = sensitivity
    except ValueError as exc:
        print(f"  ✗ Invalid metadata: {exc}")
        return False
    for name, passed in checks.items():
        print(f"  {'✓' if passed else '✗'} {name}")
    return all(checks.values())


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("identity_file")
    parser.add_argument("--manual-only", action="store_true", help="omit Reticulum checks; no reference compatibility claim")
    parser.add_argument("--expect-rns-version", help="optionally require an exact reference version for CI")
    parser.add_argument("--provider", choices=("auto", "pyca", "internal"), default="auto", help="reference provider to exercise")
    args = parser.parse_args()
    if args.manual_only and (args.expect_rns_version or args.provider != "auto"):
        parser.error("reference version/provider options cannot be used with --manual-only")
    return args


def main():
    args = parse_args()
    try:
        return verify_identity(args)
    except (OSError, ValueError) as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 1
    except ImportError as exc:
        print(f"Missing verification dependency: {exc}", file=sys.stderr)
        return 2


def verify_identity(args):
    filepath = args.identity_file
    identity = load_identity_binary(filepath)
    raw_private = identity["x25519_private"] + identity["ed25519_seed"]
    address, identity_hash, public_key = compute_lxmf_address(identity)
    print(f"File: {filepath!r} (64-byte private identity; secret bytes hidden)")
    print(f"Identity Hash: {identity_hash.hex()}")
    print(f"LXMF Address: {address.hex()}")
    metadata_result = verify_txt_file(address, identity_hash, public_key, raw_private, filepath)
    if args.manual_only:
        print("MANUAL-ONLY MODE: no Reticulum compatibility claim was tested.")
        return 1 if metadata_result is False else 0
    try:
        result = verify_with_reticulum(raw_private, args.provider)
    except Exception as exc:
        print(f"Reticulum verification failed: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Reticulum is not installed; compatibility was NOT verified.", file=sys.stderr)
        return 2
    print(f"RNS Version: {result['version']}")
    print(f"RNS Provider: {result['provider']}")
    print(f"RNS Source: {result['source']!r}")
    checks = {
        "private identity round-trip": result["private_roundtrip"],
        "public key bytes": result["public"] == public_key,
        "identity hash": result["identity_hash"] == identity_hash,
        "Destination.hash": result["destination_hash"] == address,
        "hash_from_name_and_identity": result["name_destination_hash"] == address,
        "signature round-trip": result["signature_roundtrip"],
        "encryption round-trip": result["encryption_roundtrip"],
        "metadata": metadata_result is not False,
    }
    if args.expect_rns_version:
        checks[f"RNS version is exactly {args.expect_rns_version}"] = result["version"] == args.expect_rns_version
    for name, passed in checks.items():
        print(f"  {'✓' if passed else '✗'} {name}")
    if not all(checks.values()):
        print("FAILURE: Reticulum compatibility checks failed.")
        return 1
    print(f"SUCCESS: Identity bytes and LXMF address match the installed RNS {result['version']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
