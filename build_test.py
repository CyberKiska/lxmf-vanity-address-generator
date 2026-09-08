"""Exercise build recipes only against disposable files."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("make") and shutil.which("sh"), "requires make and sh")
class BuildRecipeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name)
        shutil.copyfile(pathlib.Path(__file__).with_name("Makefile"), self.path / "Makefile")

    def test_clean_preserves_private_identities(self):
        names = ("identity", "identity.txt", "identity.tmp-recovery", "test_identity_backup", "lxmf-vanity-personal-identity")
        for name in names:
            (self.path / name).write_bytes(b"disposable sentinel")
        (self.path / "lxmf-vanity").write_bytes(b"build artifact")
        subprocess.run(["make", "clean"], cwd=self.path, capture_output=True, check=True, timeout=10)
        for name in names:
            self.assertEqual((self.path / name).read_bytes(), b"disposable sentinel")
        self.assertFalse((self.path / "lxmf-vanity").exists())

    def test_compatibility_propagates_each_stage_failure(self):
        generator = self.path / "lxmf-vanity"
        reference = self.path / "reference"
        for failing_stage in ("generation", "oracle", "verification"):
            with self.subTest(stage=failing_stage):
                generator.write_text("#!/bin/sh\nexit " + ("23" if failing_stage == "generation" else "0") + "\n")
                reference.write_text(
                    "#!/bin/sh\ncase \"$1\" in\n"
                    "scripts/rns_compatibility_oracle.py) exit " + ("23" if failing_stage == "oracle" else "0") + ";;\n"
                    "verify.py) exit " + ("23" if failing_stage == "verification" else "0") + ";;\n"
                    "*) exit 91;;\nesac\n"
                )
                generator.chmod(0o700)
                reference.chmod(0o700)
                result = subprocess.run(
                    ["make", "compatibility", "-o", "build", f"PYTHON={reference}"],
                    cwd=self.path, capture_output=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
