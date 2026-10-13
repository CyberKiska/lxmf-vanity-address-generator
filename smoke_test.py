"""Keep artifact smoke acceptance narrow around known platform limits."""

import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from scripts.smoke_artifact import DIRECTORY_SYNC_LIMIT, WINDOWS_PROTECTION_NOTICES, check_generation


class ArtifactSmokeTests(unittest.TestCase):
    def test_only_known_windows_notices_are_accepted(self):
        path = Path("disposable")
        saved = {"status": "saved", "verified_files": [str(path)], "unverified_files": [],
                 "deviations": [], "notices": [DIRECTORY_SYNC_LIMIT, *sorted(WINDOWS_PROTECTION_NOTICES)]}
        check_generation(SimpleNamespace(returncode=0, stdout=json.dumps(saved)), "windows", path)
        with self.assertRaises(ValueError):
            check_generation(SimpleNamespace(returncode=0, stdout=json.dumps(saved)), "linux", path)
        clean = saved | {"notices": []}
        check_generation(SimpleNamespace(returncode=0, stdout=json.dumps(clean)), "linux", path)
        for code, change in ((3, {"status": "partial", "deviations": ["metadata could not be saved"]}),
                             (0, {"unverified_files": ["retained"]}),
                             (0, {"verified_files": ["another-file"]}),
                             (1, {"status": "failed"}),
                             (0, {"notices": [DIRECTORY_SYNC_LIMIT, "something else"]})):
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_generation(SimpleNamespace(returncode=code, stdout=json.dumps(saved | change)),
                                 "windows", path)
