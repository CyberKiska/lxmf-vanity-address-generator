import io
import json
import unittest
from unittest.mock import patch

from scripts.install_reference import resolve_latest


class ReferenceSelectionTests(unittest.TestCase):
    def resolve(self, version, files):
        data = {"info": {"version": version}, "releases": {version: files}}
        with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(data).encode())):
            return resolve_latest("rns")

    def test_exact_stable_version_is_selected_without_wheel_fallback(self):
        self.assertEqual(self.resolve("1.5.7", [{"yanked": False, "packagetype": "sdist"}]), "1.5.7")

    def test_prereleases_and_yanked_releases_fail_closed(self):
        for version, files in (("1.6rc1", [{"yanked": False}]), ("1.5.7", [{"yanked": True}])):
            with self.assertRaises(ValueError):
                self.resolve(version, files)

    def test_latest_prerelease_or_yanked_release_cannot_hide_stable(self):
        data = {"info": {"version": "2.0rc1"}, "releases": {
            "2.0rc1": [{"yanked": False}], "1.6.0": [{"yanked": True}],
            "1.5.7": [{"yanked": False}], "1.5.6": [{"yanked": False}]}}
        with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(data).encode())):
            self.assertEqual(resolve_latest("rns"), "1.5.7")
