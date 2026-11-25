"""Prove the Rust dependency guard detects each failure case, using synthetic cargo metadata only."""

import copy
import unittest

from scripts.check_rust_deps import (CRATES_IO, check_build_config, check_build_time, check_features,
                                     check_members, check_packages, check_sources, check_target,
                                     generate, snapshot)

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
TARGET = "aarch64-apple-darwin"


def make_metadata(members=None, packages=None):
    """members: {name: [direct dependency names]}; packages: {(name, version): options}."""
    members = {"app": ["lib-a"]} if members is None else members
    packages = {("lib-a", "1.0.0"): {"features": ["std"]}} if packages is None else packages
    entries, nodes, member_ids = [], [], []
    for name, dependencies in members.items():
        identifier = f"path+file:///work/{name}#{name}@2.0.0-dev"
        member_ids.append(identifier)
        entries.append({"id": identifier, "name": name, "version": "2.0.0-dev", "source": None,
                        "targets": [{"kind": ["bin"]}],
                        "dependencies": [{"name": d, "kind": None} for d in dependencies]})
        nodes.append({"id": identifier, "features": []})
    for (name, version), options in packages.items():
        identifier = f"{REGISTRY}#{name}@{version}"
        entries.append({"id": identifier, "name": name, "version": version,
                        "source": options.get("source", REGISTRY),
                        "targets": [{"kind": [kind]} for kind in options.get("kinds", ["lib"])],
                        "dependencies": []})
        nodes.append({"id": identifier, "features": options.get("features", [])})
    return {"packages": entries, "workspace_members": member_ids, "resolve": {"nodes": nodes}}


def reviewed(metadata):
    """An allowlist that approves exactly this metadata, with every build-time package reviewed."""
    allowlist = generate({TARGET: snapshot(metadata)}, {})
    for entry in allowlist["build_time_code"].values():
        entry["build_time_code_reviewed"] = True
    return allowlist


def problems_for(metadata, allowlist, target=TARGET):
    return check_target(target, metadata, allowlist) + check_build_time(
        snapshot(metadata)[1], allowlist["build_time_code"])


class DependencyGuardTests(unittest.TestCase):
    def setUp(self):
        self.metadata = make_metadata()
        self.allowlist = reviewed(self.metadata)

    def test_matching_graph_has_no_problems(self):
        self.assertEqual(problems_for(self.metadata, self.allowlist), [])

    def test_unlisted_direct_dependency_of_a_member_is_rejected(self):
        changed = make_metadata(members={"app": ["lib-a", "extra"]})
        self.assertTrue(any("direct dependencies differ" in p and "+ extra" in p
                            for p in check_members(snapshot(changed)[0], self.allowlist)))

    def test_dependency_of_any_kind_counts_as_direct(self):
        changed = copy.deepcopy(self.metadata)
        changed["packages"][0]["dependencies"].append({"name": "dev-only", "kind": "dev"})
        self.assertTrue(check_members(snapshot(changed)[0], self.allowlist))

    def test_extra_or_missing_workspace_member_is_rejected(self):
        extra = make_metadata(members={"app": ["lib-a"], "tool": []})
        self.assertIn("unexpected workspace member tool", check_members(snapshot(extra)[0], self.allowlist))
        self.assertIn("workspace member app is missing", check_members({}, self.allowlist))

    def test_added_removed_and_upgraded_packages_are_shown_as_a_diff(self):
        added = make_metadata(packages={("lib-a", "1.0.0"): {"features": ["std"]}, ("lib-b", "0.1.0"): {}})
        found = check_packages(snapshot(added)[1], self.allowlist["targets"][TARGET])
        self.assertEqual(len(found), 1)
        self.assertIn("+ lib-b 0.1.0", found[0])
        upgraded = make_metadata(packages={("lib-a", "1.0.1"): {"features": ["std"]}})
        found = check_packages(snapshot(upgraded)[1], self.allowlist["targets"][TARGET])
        self.assertTrue("+ lib-a 1.0.1" in found[0] and "- lib-a 1.0.0" in found[0])
        removed = make_metadata(packages={})
        self.assertIn("- lib-a 1.0.0", check_packages(snapshot(removed)[1], self.allowlist["targets"][TARGET])[0])

    def test_changed_enabled_feature_is_rejected(self):
        changed = make_metadata(packages={("lib-a", "1.0.0"): {"features": ["std", "serde"]}})
        found = check_features(snapshot(changed)[1], self.allowlist["targets"][TARGET])
        self.assertEqual(len(found), 1)
        self.assertIn("+ serde", found[0])
        dropped = make_metadata(packages={("lib-a", "1.0.0"): {"features": []}})
        self.assertIn("- std", check_features(snapshot(dropped)[1], self.allowlist["targets"][TARGET])[0])

    def test_git_path_and_other_registry_sources_are_rejected(self):
        for source in ("git+https://example.invalid/lib#abc", None, "registry+https://example.invalid/index"):
            with self.subTest(source=source):
                changed = make_metadata(packages={("lib-a", "1.0.0"): {"features": ["std"], "source": source}})
                self.assertEqual(len(check_sources(snapshot(changed)[1])), 1)
        self.assertIn(REGISTRY, CRATES_IO)

    def test_unreviewed_build_script_or_proc_macro_is_rejected(self):
        for kind, label in (("custom-build", "build-script"), ("proc-macro", "proc-macro")):
            with self.subTest(kind=kind):
                metadata = make_metadata(packages={("lib-a", "1.0.0"): {"features": [], "kinds": ["lib", kind]}})
                allowlist = generate({TARGET: snapshot(metadata)}, {})
                self.assertFalse(allowlist["build_time_code"]["lib-a 1.0.0"]["build_time_code_reviewed"])
                found = check_build_time(snapshot(metadata)[1], allowlist["build_time_code"])
                self.assertEqual(len(found), 1)
                self.assertIn(label, found[0])
                allowlist["build_time_code"]["lib-a 1.0.0"]["build_time_code_reviewed"] = True
                self.assertEqual(check_build_time(snapshot(metadata)[1], allowlist["build_time_code"]), [])

    def test_build_time_code_missing_from_the_table_or_with_other_kind_is_rejected(self):
        metadata = make_metadata(packages={("lib-a", "1.0.0"): {"features": [], "kinds": ["custom-build"]}})
        packages = snapshot(metadata)[1]
        self.assertTrue(check_build_time(packages, {}))
        wrong = {"lib-a 1.0.0": {"kinds": ["proc-macro"], "build_time_code_reviewed": True}}
        self.assertTrue(check_build_time(packages, wrong))

    def test_review_does_not_carry_over_to_a_new_version(self):
        metadata = make_metadata(packages={("lib-a", "1.0.0"): {"features": [], "kinds": ["custom-build"]}})
        allowlist = reviewed(metadata)
        upgraded = make_metadata(packages={("lib-a", "1.0.1"): {"features": [], "kinds": ["custom-build"]}})
        regenerated = generate({TARGET: snapshot(upgraded)}, allowlist)
        self.assertFalse(regenerated["build_time_code"]["lib-a 1.0.1"]["build_time_code_reviewed"])
        same = generate({TARGET: snapshot(metadata)}, allowlist)
        self.assertTrue(same["build_time_code"]["lib-a 1.0.0"]["build_time_code_reviewed"])

    def test_target_without_a_reviewed_list_is_rejected(self):
        self.assertEqual(check_target("x86_64-pc-windows-msvc", self.metadata, self.allowlist),
                         ["no reviewed package list for x86_64-pc-windows-msvc"])

    def test_regeneration_keeps_the_reviewed_member_lists(self):
        policy = {"app": ["lib-a"]}
        changed = make_metadata(members={"app": ["lib-a", "extra"]})
        self.assertEqual(generate({TARGET: snapshot(changed)}, {"members": policy})["members"], policy)


class BuildConfigTests(unittest.TestCase):
    def test_backend_cfgs_in_rustflags_variables_are_rejected(self):
        for name in ("getrandom_backend", "curve25519_dalek_backend", "curve25519_dalek_bits"):
            for variable in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"):
                with self.subTest(name=name, variable=variable):
                    value = f'-C opt-level=3\x1f--cfg\x1f{name}="x"'
                    found = check_build_config({variable: value}, {})
                    self.assertEqual(found, [f"environment variable {variable} sets {name}"])

    def test_backend_cfgs_in_cargo_config_files_are_rejected(self):
        text = '[build]\nrustflags = ["--cfg", "getrandom_backend=\\"rdrand\\""]\n'
        self.assertEqual(check_build_config({}, {"/work/.cargo/config.toml": text}),
                         ["Cargo config /work/.cargo/config.toml sets getrandom_backend"])

    def test_unrelated_flags_and_variables_are_accepted(self):
        environment = {"RUSTFLAGS": "-D warnings", "PATH": "getrandom_backend", "CARGO_HOME": "/x"}
        self.assertEqual(check_build_config(environment, {"/c": "[net]\nretry = 3\n"}), [])


if __name__ == "__main__":
    unittest.main()
