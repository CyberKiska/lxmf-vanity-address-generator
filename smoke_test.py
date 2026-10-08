"""Keep artifact smoke acceptance narrow around known platform limits."""

import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from scripts.smoke_artifact import check_generation


class ArtifactSmokeTests(unittest.TestCase):
    def test_only_windows_directory_limit_is_accepted(self):
        path = Path("disposable")
        warning = "directory sync unsupported on this filesystem; power-loss durability is not verified"
        saved = {"status": "partial", "verified_files": [str(path)],
                 "unverified_files": [], "deviations": [warning]}
        result = SimpleNamespace(returncode=3, stdout=json.dumps(saved))
        check_generation(result, "windows", path)
        with self.assertRaises(ValueError):
            check_generation(result, "linux", path)
        for change in ({"deviations": [warning, "metadata could not be saved"]},
                       {"unverified_files": ["retained"]},
                       {"verified_files": ["another-file"]},
                       {"status": "failed"},
                       {"deviations": [warning + "\ninjected close failure"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_generation(SimpleNamespace(returncode=3, stdout=json.dumps(saved | change)),
                                 "windows", path)
