import argparse
import base64
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import verify


class VerifyScriptTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.identity_path = os.path.join(self.tempdir.name, "identity")
        with open(self.identity_path, "wb") as identity_file:
            identity_file.write(bytes(range(64)))

        self.manual_result = (bytes.fromhex("11" * 16), bytes.fromhex("22" * 16), bytes(64))

    def run_main(self, *, manual_only, reticulum_result):
        args = argparse.Namespace(
            identity_file=self.identity_path,
            manual_only=manual_only,
        )
        with mock.patch.object(verify, "parse_args", return_value=args), mock.patch.object(
            verify, "compute_lxmf_address", return_value=self.manual_result
        ), mock.patch.object(
            verify, "verify_with_reticulum", return_value=reticulum_result
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                return verify.main()

    def valid_reticulum_result(self):
        return {
            "version": verify.EXPECTED_RNS_VERSION,
            "public": self.manual_result[2],
            "identity_hash": self.manual_result[1],
            "destination_hash": self.manual_result[0],
            "name_destination_hash": self.manual_result[0],
            "private_roundtrip": True,
            "signature_roundtrip": True,
            "encryption_roundtrip": True,
        }

    def test_missing_reticulum_fails_closed(self):
        self.assertEqual(self.run_main(manual_only=False, reticulum_result=None), 2)

    def test_manual_only_requires_explicit_flag(self):
        self.assertEqual(self.run_main(manual_only=True, reticulum_result=None), 0)

    def test_exact_reticulum_version_is_required(self):
        result = self.valid_reticulum_result()
        result["version"] = "1.3.8"
        self.assertEqual(self.run_main(manual_only=False, reticulum_result=result), 1)

    def test_exact_reticulum_version_and_roundtrips_pass(self):
        self.assertEqual(
            self.run_main(
                manual_only=False,
                reticulum_result=self.valid_reticulum_result(),
            ),
            0,
        )

    def test_public_metadata_rejects_private_exports(self):
        address, identity_hash, public_key = self.manual_result
        raw_private = bytes(range(64))
        with open(self.identity_path + ".txt", "w", encoding="utf-8") as info:
            info.write(
                "\n".join(
                    [
                        f"Address (LXMF): {address.hex()}",
                        f"Identity Hash:  {identity_hash.hex()}",
                        f"Full Specifier: <lxmf.delivery.{identity_hash.hex()}:{address.hex()}>",
                        f"  X25519 Public:  {public_key[:32].hex()}",
                        f"  Ed25519 Public: {public_key[32:].hex()}",
                        f"  Combined:       {public_key.hex()}",
                        "This metadata file contains public information only.",
                        base64.urlsafe_b64encode(raw_private).decode("ascii"),
                    ]
                )
            )

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(
                verify.verify_txt_file(
                    address,
                    identity_hash,
                    public_key,
                    raw_private,
                    self.identity_path,
                )
            )


if __name__ == "__main__":
    unittest.main()
