#!/usr/bin/env python3
"""Generate or verify the deterministic RNS 1.4.2 compatibility fixture."""

import argparse
import difflib
import hashlib
import json
import sys
from pathlib import Path


EXPECTED_RNS_VERSION = "1.4.2"
RNS_REFERENCE_COMMIT = "b48b96e61676504e0a4e527b33b9a0b4495c6872"
RAW_X25519_INPUT = bytes.fromhex(
    "070102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1edf"
)
ED25519_SEED = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
)


def clamp_x25519(raw):
    canonical = bytearray(raw)
    canonical[0] &= 248
    canonical[31] &= 127
    canonical[31] |= 64
    return bytes(canonical)


def build_fixture():
    try:
        import RNS
    except ImportError as exc:
        raise RuntimeError("RNS 1.4.2 is required to run the compatibility oracle") from exc

    actual_version = getattr(RNS, "__version__", "unknown")
    if actual_version != EXPECTED_RNS_VERSION:
        raise RuntimeError(
            f"expected RNS {EXPECTED_RNS_VERSION}, found {actual_version}"
        )

    canonical_x25519 = clamp_x25519(RAW_X25519_INPUT)
    canonical_private = canonical_x25519 + ED25519_SEED
    canonical_identity = RNS.Identity.from_bytes(canonical_private)
    if canonical_identity is None:
        raise RuntimeError("RNS rejected the canonical deterministic identity")

    unmasked_private = RAW_X25519_INPUT + ED25519_SEED
    unmasked_identity = RNS.Identity.from_bytes(unmasked_private)
    if unmasked_identity is None:
        raise RuntimeError("RNS rejected the unmasked round-trip test identity")

    canonical_address = RNS.Destination.hash(
        canonical_identity, "lxmf", "delivery"
    )
    unmasked_address = RNS.Destination.hash(
        unmasked_identity, "lxmf", "delivery"
    )
    public_key = canonical_identity.get_public_key()

    return {
        "rns_version": actual_version,
        "rns_reference_commit": RNS_REFERENCE_COMMIT,
        "raw_candidate_input": unmasked_private.hex(),
        "x25519_private": canonical_x25519.hex(),
        "x25519_public": public_key[:32].hex(),
        "ed25519_seed": ED25519_SEED.hex(),
        "ed25519_public": public_key[32:].hex(),
        "identity_hash": canonical_identity.hash.hex(),
        "lxmf_name_hash": hashlib.sha256(b"lxmf.delivery").digest()[:10].hex(),
        "lxmf_address": canonical_address.hex(),
        "canonical_private_roundtrip": (
            canonical_identity.get_private_key() == canonical_private
        ),
        "unmasked_private_roundtrip_preserved": (
            unmasked_identity.get_private_key() == unmasked_private
        ),
        "unmasked_and_canonical_addresses_equal": (
            unmasked_address == canonical_address
        ),
    }


def encoded_fixture():
    return json.dumps(build_fixture(), indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--check", metavar="PATH", type=Path)
    output.add_argument("--write", metavar="PATH", type=Path)
    args = parser.parse_args()

    try:
        generated = encoded_fixture()
    except Exception as exc:
        print(f"oracle error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        existing = args.check.read_text(encoding="utf-8")
        if existing == generated:
            print(
                f"RNS {EXPECTED_RNS_VERSION} compatibility fixture matches {args.check}"
            )
            return 0
        print(
            "".join(
                difflib.unified_diff(
                    existing.splitlines(keepends=True),
                    generated.splitlines(keepends=True),
                    fromfile=str(args.check),
                    tofile="generated",
                )
            ),
            file=sys.stderr,
            end="",
        )
        return 1

    if args.write:
        args.write.write_text(generated, encoding="utf-8")
        print(f"wrote {args.write}")
        return 0


    print(generated, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
