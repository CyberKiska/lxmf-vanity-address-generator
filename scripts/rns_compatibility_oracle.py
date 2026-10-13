#!/usr/bin/env python3
"""Check deterministic identity vectors and CLI interoperability against RNS.

Version/provenance pins belong to the CI installation, not to the expected
cryptographic bytes. All private inputs in this fixture are PUBLIC TEST DATA.
"""

import argparse
import base64
import contextlib
import hashlib
import io
import importlib
import inspect
import re
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify

MESSAGE = b"lxmf-vanity cross-language compatibility probe"
PEER_PRIVATE = bytes([0x42]) * 32


class Mismatch(ValueError):
    """A tested mismatch with a public diagnostic."""


def require(condition, message):
    if not condition:
        raise Mismatch(message)


def candidate_inputs():
    original = json.loads((Path(__file__).resolve().parent.parent / "testdata/rns-1.4.2-golden.json").read_text())
    yield bytes(64)
    yield bytes([255]) * 64
    yield bytes.fromhex(original["raw_candidate_input"])
    for i in range(64):
        raw = bytearray(64)
        raw[i] = 1
        yield bytes(raw)
    for i in range(64):
        yield hashlib.sha512(b"PUBLIC LXMF TEST VECTOR" + bytes([i])).digest()


class IncompleteEnvironment(Exception):
    """A specifically identified missing dependency."""


class APIDrift(Exception):
    """A recognised interface change prevents a requested check."""


def load_lxmf(mode):
    if mode == "off":
        return None
    try:
        return importlib.import_module("LXMF")
    except ModuleNotFoundError as exc:
        if exc.name != "LXMF":
            raise
        if mode == "required":
            raise IncompleteEnvironment("LXMF is not installed") from exc
        print("LXMF unavailable: delivery registration was not checked", file=sys.stderr)
        return None


def check_lxmf_delivery(RNS, LXMF, identity, expected):
    if not hasattr(LXMF, "APP_NAME") or not hasattr(LXMF, "LXMRouter"):
        raise APIDrift("LXMF app-name/router API unavailable")
    require(LXMF.APP_NAME == "lxmf", "LXMF app name mismatch")
    method = getattr(LXMF.LXMRouter, "register_delivery_identity", None)
    if method is None or "identity" not in inspect.signature(method).parameters:
        raise APIDrift("LXMF delivery-registration API changed")
    # Do not start a router or Reticulum instance. Execute upstream naming/hash
    # construction, isolating only network registration and external storage.
    with tempfile.TemporaryDirectory(prefix="lxmf-delivery-") as directory:
        router = LXMF.LXMRouter.__new__(LXMF.LXMRouter)
        router.delivery_destinations = {}
        router.ratchetpath = directory
        router.enforce_ratchets = False
        with patch.object(RNS.Transport, "register_destination"):
            destination = router.register_delivery_identity(identity)
        require(destination is not None and destination.hash == expected,
                "LXMF registered delivery address mismatch")


def build_fixture(RNS, LXMF=None):
    vectors = []
    peer = RNS.Cryptography.X25519PrivateKey.from_private_bytes(PEER_PRIVATE).public_key()
    for index, raw in enumerate(candidate_inputs()):
        private = bytearray(raw)
        private[0] &= 248
        private[31] = (private[31] & 127) | 64
        private = bytes(private)
        identity = RNS.Identity.from_bytes(private)
        unmasked = RNS.Identity.from_bytes(raw)
        require(identity is not None and unmasked is not None, f"vector {index}: reference rejected input")
        require(identity.get_private_key() == private, f"vector {index}: masked private round-trip")
        require(unmasked.get_private_key() == raw, f"vector {index}: raw private round-trip")
        require(identity.get_public_key() == unmasked.get_public_key(), f"vector {index}: raw/masked public keys")
        address = RNS.Destination.hash(identity, "lxmf", "delivery")
        require(address == RNS.Destination.hash_from_name_and_identity("lxmf.delivery", identity),
                f"vector {index}: destination APIs disagree")
        # Only networking is disabled: execute the real constructor and hashing.
        with patch.object(RNS.Transport, "register_destination"):
            destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
        require(destination.hash == address, f"vector {index}: destination constructor")
        if LXMF is not None:
            check_lxmf_delivery(RNS, LXMF, identity, address)
        signature = identity.sign(MESSAGE)
        public = RNS.Identity(create_keys=False)
        public.load_public_key(identity.get_public_key())
        require(public.validate(signature, MESSAGE), f"vector {index}: signature round-trip")
        require(identity.decrypt(public.encrypt(MESSAGE)) == MESSAGE, f"vector {index}: encryption round-trip")
        vectors.append({
            "raw": raw.hex(), "private": private.hex(), "public": identity.get_public_key().hex(),
            "hash": identity.hash.hex(), "address": address.hex(), "signature": signature.hex(),
            "shared": identity.prv.exchange(peer).hex(),
        })
    return {"message": MESSAGE.decode("ascii"), "peer_private": PEER_PRIVATE.hex(), "vectors": vectors}


def check_rnid_import(bootstrap, value, expected_address, encoding=None):
    label = {None: "file", "-b": "Base64", "-B": "Base32"}[encoding]
    # URL-safe Base64 can begin with '-'. Bind the value to -M so argparse
    # cannot interpret private identity bytes as another command-line option.
    arguments = ["-i", str(value)] if encoding is None else ["-M=" + value, encoding]
    result = subprocess.run(
        [sys.executable, "-c", bootstrap, *arguments, "-N", "-H", "lxmf.delivery"],
        capture_output=True, text=True, timeout=30,
    )
    # Neither the command nor captured output is safe to log: either can
    # contain a private export, including in argparse error messages.
    if result.returncode == 2 and re.search(
        r"unrecognized arguments: (?:-N|-H)(?:\s|$)", result.stderr
    ):
        raise APIDrift("rnid no-network/hash option API changed; import check skipped")
    require(result.returncode == 0, f"rnid {label} import exited with status {result.returncode}")
    require(expected_address in result.stdout, f"rnid {label} import did not report the expected destination")


def check_cli(RNS, binary, provider, checks="all"):
    interop = checks in ("interop", "all")
    binary = str(binary.resolve())
    repository = str(Path(__file__).resolve().parent.parent)
    bootstrap = (f"import sys; sys.path.insert(0, {repository!r}); import verify; "
                 f"verify.load_reticulum({provider!r}); from RNS.Utilities.rnid import main; main()")
    for exports in (False, True):
        with tempfile.TemporaryDirectory(prefix="lxmf-compat-") as directory:
            path = Path(directory) / "identity"
            args = [binary, "--prefix", "a", "--postfix", "b", "--workers", "2", "--out", str(path)]
            if os.name == "nt":
                args.append("--allow-inherited-windows-acl")
            if exports:
                args.append("--include-private-exports")
            subprocess.run(args, check=True, capture_output=True, timeout=30)
            raw = verify.read_limited_file(path, 64)
            require(len(raw) == 64, "CLI saved an invalid private identity length")
            identity = RNS.Identity.from_file(str(path))
            require(identity is not None and identity.get_private_key() == raw, "RNS file round-trip failed")
            address = RNS.Destination.hash(identity, "lxmf", "delivery")
            require(address.hex().startswith("a") and address.hex().endswith("b"), "CLI vanity pattern mismatch")
            with contextlib.redirect_stdout(io.StringIO()):
                args = argparse.Namespace(no_metadata=False, identity_file=str(path), provider=provider,
                                          expect_rns_version=None, manual_only=False)
                require(verify.verify_identity(args) == 0, "CLI metadata/reference verification failed")
            if interop:
                check_rnid_import(bootstrap, path, address.hex())
            if exports and interop:
                fields, _ = verify.parse_metadata(path.with_suffix(".txt").read_text(encoding="utf-8"))
                check_rnid_import(bootstrap, fields[verify.BASE64_LABEL], address.hex(), "-b")
                check_rnid_import(bootstrap, fields[verify.BASE32_LABEL], address.hex(), "-B")

    if not interop:
        print("CLI private-file and metadata core checks passed")
        return

    # PUBLIC TEST KEY: the corpus's masked all-FF input guarantees a leading
    # hyphen, so this regression is tested on every run instead of by chance.
    private = bytes([248]) + bytes([255]) * 30 + bytes([127]) + bytes([255]) * 32
    exported = base64.urlsafe_b64encode(private).decode("ascii")
    require(exported.startswith("-"), "invalid leading-hyphen regression input")
    identity = RNS.Identity.from_bytes(private)
    address = RNS.Destination.hash(identity, "lxmf", "delivery").hex()
    check_rnid_import(bootstrap, exported, address, "-b")
    print("rnid leading-hyphen Base64 import passed")
    print("CLI private-file, metadata, vanity pattern and rnid export round-trips passed")


def failure_code(exc):
    if isinstance(exc, IncompleteEnvironment):
        return 2, str(exc)
    if isinstance(exc, APIDrift):
        return 3, str(exc)
    if isinstance(exc, ModuleNotFoundError) and exc.name in {"RNS", "cryptography", "serial", "cffi"}:
        return 2, "required reference dependency is unavailable"
    if isinstance(exc, subprocess.SubprocessError):
        return 1, "unexpected interoperability subprocess failure or timeout"
    if isinstance(exc, Mismatch):
        return 1, str(exc)
    # Do not dump arbitrary upstream exceptions or commands containing exports.
    return 1, "unexpected oracle/runtime failure: " + type(exc).__name__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--check", type=Path)
    output.add_argument("--write", type=Path)
    parser.add_argument("--checks", choices=("core", "interop", "all"), default="all")
    parser.add_argument("--lxmf", choices=("required", "auto", "off"), default="auto")
    parser.add_argument("--binary", type=Path, help="also test a compiled Go CLI")
    parser.add_argument("--expect-rns-version", help="optional exact CI version assertion")
    parser.add_argument("--provider", choices=("auto", "pyca", "internal"), default="auto")
    args = parser.parse_args()
    try:
        RNS = verify.load_reticulum(args.provider)
        version = getattr(RNS, "__version__", "unknown")
        if args.expect_rns_version:
            require(version == args.expect_rns_version, f"expected RNS {args.expect_rns_version}, found {version}")
        print(f"Reference: RNS {version}; {RNS.Cryptography.backend()}; source {RNS.__file__!r}", file=sys.stderr)
        LXMF = load_lxmf(args.lxmf) if args.checks in ("core", "all") else None
        if LXMF is not None:
            print(f"LXMF reference: {getattr(LXMF, '__version__', 'unknown')}", file=sys.stderr)
        fixture = build_fixture(RNS, LXMF) if args.checks in ("core", "all") else None
        if args.check and fixture is not None:
            expected = json.loads(args.check.read_text(encoding="utf-8"))
            require(expected == fixture,
                    "cryptographic fixture mismatch (reference version alone is not a mismatch)")
            print(f"All {len(fixture['vectors'])} deterministic vectors match {args.check}")
        elif args.write and fixture is not None:
            args.write.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"Wrote public test vectors to {args.write}")
        elif not args.binary and fixture is not None:
            print(json.dumps(fixture, indent=2, sort_keys=True))
        if args.binary:
            check_cli(RNS, args.binary, args.provider, args.checks)
        return 0
    except Exception as exc:
        code, message = failure_code(exc)
        print(f"Oracle failed (class {code}): {message}", file=sys.stderr)
        return code


if __name__ == "__main__":
    sys.exit(main())
