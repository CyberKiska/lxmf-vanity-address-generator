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
