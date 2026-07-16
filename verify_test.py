import argparse
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

    def test_missing_reticulum_fails_closed(self):
        self.assertEqual(self.run_main(manual_only=False, reticulum_result=None), 2)

    def test_manual_only_requires_explicit_flag(self):
        self.assertEqual(self.run_main(manual_only=True, reticulum_result=None), 0)


if __name__ == "__main__":
    unittest.main()
