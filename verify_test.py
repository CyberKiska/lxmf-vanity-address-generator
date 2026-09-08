import argparse
import base64
import contextlib
import io
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import verify


class VerifyScriptTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.identity_path = os.path.join(self.tempdir.name, "identity")
        self.private = bytes(range(64))
        pathlib.Path(self.identity_path).write_bytes(self.private)
        self.manual_result = (bytes.fromhex("11" * 16), bytes.fromhex("22" * 16), bytes(64))

    def run_main(self, result, *, manual_only=False, expected=None):
        args = argparse.Namespace(identity_file=self.identity_path, manual_only=manual_only, expect_rns_version=expected, provider="auto")
        with mock.patch.object(verify, "parse_args", return_value=args), mock.patch.object(verify, "compute_lxmf_address", return_value=self.manual_result), mock.patch.object(verify, "verify_with_reticulum", return_value=result):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return verify.main()

    def reference_result(self, version="1.5.2"):
        return {
            "version": version, "provider": "test provider", "source": "test reference",
            "public": self.manual_result[2], "identity_hash": self.manual_result[1],
            "destination_hash": self.manual_result[0], "name_destination_hash": self.manual_result[0],
            "private_roundtrip": True, "signature_roundtrip": True, "encryption_roundtrip": True,
        }

    def test_missing_reference_fails_closed(self):
        self.assertEqual(self.run_main(None), 2)
        self.assertEqual(self.run_main(None, manual_only=True), 0)

    def test_matching_behavior_accepts_different_versions(self):
        for version in ("1.4.2", "1.5.2", "future-test-version"):
            with self.subTest(version=version):
                self.assertEqual(self.run_main(self.reference_result(version)), 0)

    def test_optional_exact_version_assertion(self):
        self.assertEqual(self.run_main(self.reference_result(), expected="1.5.2"), 0)
        self.assertEqual(self.run_main(self.reference_result(), expected="1.4.2"), 1)

    def test_each_cryptographic_mismatch_fails(self):
        for key in ("public", "identity_hash", "destination_hash", "name_destination_hash", "private_roundtrip", "signature_roundtrip", "encryption_roundtrip"):
            with self.subTest(check=key):
                result = self.reference_result()
                result[key] = False if isinstance(result[key], bool) else b"wrong"
                self.assertEqual(self.run_main(result), 1)

    def metadata(self, private=False):
        address, identity_hash, public_key = self.manual_result
        lines = [
            f"Address (LXMF): {address.hex()}", f"Identity Hash: {identity_hash.hex()}",
            f"Full Specifier: <lxmf.delivery.{identity_hash.hex()}:{address.hex()}>",
            f"  X25519 Public: {public_key[:32].hex()}", f"  Ed25519 Public: {public_key[32:].hex()}",
            f"  Combined: {public_key.hex()}",
        ]
        if private:
            lines += [verify.PRIVATE_WARNING, verify.BASE64_LABEL + ":", "  " + base64.urlsafe_b64encode(self.private).decode(), verify.BASE32_LABEL + ":", "  " + base64.b32encode(self.private).decode()]
        else:
            lines.append(verify.PUBLIC_LABEL)
        return "\n".join(lines)

    def check_metadata(self, content):
        pathlib.Path(self.identity_path + ".txt").write_text(content, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            return verify.verify_txt_file(*self.manual_result, self.private, self.identity_path)

    def test_valid_public_and_private_metadata(self):
        self.assertTrue(self.check_metadata(self.metadata()))
        self.assertTrue(self.check_metadata(self.metadata(private=True)))

    def test_metadata_rejects_decoys_and_duplicate_fields(self):
        valid = self.metadata()
        for label in ("Address (LXMF)", "Identity Hash", "Full Specifier", "X25519 Public", "Ed25519 Public", "Combined"):
            with self.subTest(field=label):
                real = next(line for line in valid.splitlines() if line.strip().startswith(label + ":"))
                self.assertFalse(self.check_metadata(valid.replace(real, label + ": WRONG") + "\n# decoy: " + real))
                self.assertFalse(self.check_metadata(valid + "\n" + real))

    def test_private_exports_and_labels_cannot_be_misrepresented(self):
        export64 = base64.urlsafe_b64encode(self.private).decode()
        export32 = base64.b32encode(self.private).decode()
        for content in (
            self.metadata() + "\n" + export64,
            self.metadata() + "\n" + self.private.hex(),
            self.metadata(private=True) + "\n" + verify.PUBLIC_LABEL,
            self.metadata(private=True).replace(export32, "INVALID"),
            self.metadata(private=True).replace(verify.PRIVATE_WARNING, ""),
            self.metadata(private=True) + "\n" + verify.BASE64_LABEL + ":\n" + export64,
        ):
            self.assertFalse(self.check_metadata(content))

    def test_invalid_file_sizes_and_nonregular_files(self):
        for size in (0, 32, 63, 65, 100000):
            pathlib.Path(self.identity_path).write_bytes(bytes(size))
            with self.assertRaises(ValueError):
                verify.load_identity_binary(self.identity_path)
        if hasattr(os, "mkfifo"):
            fifo = self.identity_path + ".fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                verify.read_limited_file(fifo, 64)

    def test_oversized_metadata_fails_without_unbounded_read(self):
        pathlib.Path(self.identity_path + ".txt").write_bytes(b"x" * (verify.MAX_METADATA_SIZE + 1))
        self.assertEqual(self.run_main(self.reference_result()), 1)

    def test_missing_metadata_is_optional(self):
        self.assertIsNone(verify.verify_txt_file(*self.manual_result, self.private, self.identity_path))


if __name__ == "__main__":
    unittest.main()
