"""Test the fixture converter: round trip on a small sample, and --check on stale or missing files."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts import gen_rust_test_vectors as gen

VECTOR = {"raw": "00" * 64, "private": "11" * 64, "public": "22" * 64, "hash": "33" * 16,
          "address": "44" * 16, "signature": "55" * 64, "shared": "66" * 32}
SAMPLE = {"message": "héllo", "peer_private": "42" * 32,
          "vectors": [VECTOR, {**VECTOR, "raw": "ff" * 64, "address": "0a" * 16}]}
GOLDEN = {"rns_version": "1.4.2", "identity_hash": "aa" * 16, "canonical_private_roundtrip": True,
          "unmasked_private_roundtrip_preserved": False}


class ConverterTest(unittest.TestCase):
    def test_two_vector_sample_round_trips(self):
        lines = gen.convert_vectors(SAMPLE).split("\n")
        self.assertEqual(lines[0], "message " + "héllo".encode().hex())
        self.assertEqual(lines[1], "peer_private " + "42" * 32)
        self.assertEqual(lines[4], "")
        for line, vector in zip(lines[2:4], SAMPLE["vectors"]):
            fields = line.split(" ")
            self.assertEqual(dict(zip((name for name, _ in gen.VECTOR_FIELDS), fields)), vector)

    def test_golden_is_sorted_key_value_lines(self):
        self.assertEqual(gen.convert_golden(GOLDEN),
                         "canonical_private_roundtrip true\nidentity_hash " + "aa" * 16 +
                         "\nrns_version 1.4.2\nunmasked_private_roundtrip_preserved false\n")

    def test_output_is_deterministic_with_unix_line_endings(self):
        self.assertEqual(gen.convert_vectors(SAMPLE), gen.convert_vectors(SAMPLE))
        self.assertNotIn("\r", gen.convert_vectors(SAMPLE))

    def test_malformed_vector_is_rejected(self):
        for field, value in (("raw", "00" * 63), ("hash", "G" * 32), ("shared", "AB" * 32)):
            bad = {**SAMPLE, "vectors": [{**VECTOR, field: value}]}
            with self.assertRaises(ValueError, msg=field):
                gen.convert_vectors(bad)

    def test_committed_files_are_fresh(self):
        self.assertEqual(gen.stale(gen.outputs()), [])


class CheckModeTest(unittest.TestCase):
    def run_main(self, *args):
        with contextlib.redirect_stderr(io.StringIO()):
            return gen.main(list(args))

    def test_check_detects_missing_and_changed_files(self):
        with tempfile.TemporaryDirectory() as root:
            sources, target = Path(root, "src"), Path(root, "out")
            sources.mkdir()
            (sources / "rns-identity-vectors.json").write_text(json.dumps(SAMPLE))
            (sources / "rns-1.4.2-golden.json").write_text(json.dumps(GOLDEN))
            options = ("--sources", str(sources), "--target", str(target))
            self.assertEqual(self.run_main("--check", *options), 1)  # missing
            self.assertEqual(self.run_main(*options), 0)
            self.assertEqual(self.run_main("--check", *options), 0)
            (target / "rns-1.4.2-golden.txt").write_text("rns_version 1.4.3\n")
            self.assertEqual(self.run_main("--check", *options), 1)  # changed
            self.assertEqual(self.run_main(*options), 0)
            self.assertEqual(self.run_main("--check", *options), 0)
            (sources / "rns-identity-vectors.json").write_text(json.dumps({**SAMPLE, "message": "x"}))
            self.assertEqual(self.run_main("--check", *options), 1)  # source changed


if __name__ == "__main__":
    unittest.main()
