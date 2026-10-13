"""Regression checks for the reference CLI invocation; no RNS install needed."""

import unittest

from scripts.rns_compatibility_oracle import check_rnid_import


class RnidInvocationTests(unittest.TestCase):
    def test_leading_hyphen_export_is_an_option_value(self):
        # Exercise an actual subprocess and argparse, the parser rnid uses.
        bootstrap = """
import argparse
p = argparse.ArgumentParser()
p.add_argument('-M')
p.add_argument('-b', action='store_true')
p.add_argument('-N', action='store_true')
p.add_argument('-H')
args = p.parse_args()
assert args.M == '-public-test-value=='
assert args.b and args.N and args.H == 'lxmf.delivery'
print('expected-public-address')
"""
        check_rnid_import(bootstrap, "-public-test-value==", "expected-public-address", "-b")

    def test_failure_diagnostic_does_not_disclose_exports(self):
        for bootstrap, expected in (
            ("print('private-sentinel'); raise SystemExit(2)", "status 2"),
            ("print('private-sentinel')", "expected destination"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(ValueError) as caught:
                    check_rnid_import(bootstrap, "private-sentinel", "expected-public-address", "-b")
                self.assertIn("Base64", str(caught.exception))
                self.assertIn(expected, str(caught.exception))
                self.assertNotIn("private-sentinel", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

class OracleFailureClasses(unittest.TestCase):
    def test_failure_classes_do_not_waive_unexpected_errors(self):
        from scripts.rns_compatibility_oracle import failure_code, APIDrift, IncompleteEnvironment
        import subprocess
        for exc, expected in (
            (ValueError("tested mismatch"), 1),
            (RuntimeError("private-sentinel"), 1),
            (AttributeError("unexpected API failure"), 1),
            (ImportError("unexpected import"), 1),
            (IncompleteEnvironment("missing RNS"), 2),
            (APIDrift("recognised option change"), 3),
            (subprocess.CalledProcessError(2, ["rnid", "private-sentinel"]), 1),
        ):
            code, message = failure_code(exc)
            self.assertEqual(code, expected)
            self.assertNotIn("private-sentinel", message)

    def test_only_recognised_rnid_option_drift_is_optional(self):
        from scripts.rns_compatibility_oracle import APIDrift
        bootstrap = "import sys; print('unrecognized arguments: -N -H lxmf.delivery', file=sys.stderr); raise SystemExit(2)"
        with self.assertRaises(APIDrift):
            check_rnid_import(bootstrap, "private-sentinel", "public-address", "-b")
        with self.assertRaises(ValueError):
            check_rnid_import("raise SystemExit(2)", "private-sentinel", "public-address", "-b")

    def test_lxmf_checks_actual_aspect_and_app_name(self):
        from scripts.rns_compatibility_oracle import check_lxmf_delivery
        from types import SimpleNamespace
        class Router:
            def register_delivery_identity(self, identity):
                return SimpleNamespace(hash=b"changed-aspect")
        rns = SimpleNamespace(Transport=SimpleNamespace(register_destination=lambda: None))
        lxmf = SimpleNamespace(APP_NAME="lxmf", LXMRouter=Router)
        with self.assertRaisesRegex(ValueError, "delivery address mismatch"):
            check_lxmf_delivery(rns, lxmf, None, b"expected-delivery")
        lxmf.APP_NAME = "changed-app"
        with self.assertRaisesRegex(ValueError, "app name mismatch"):
            check_lxmf_delivery(rns, lxmf, None, b"expected-delivery")
