#!/usr/bin/env python3
"""Check the Rust workspace's resolved dependencies against rust/dependency-allowlist.json.

For each release target the guard runs `cargo metadata --locked --filter-platform <triple>` and fails
when a member declares an unlisted dependency, the resolved package set or an enabled feature differs
from the reviewed list, a package comes from a git or path source, a package with a build script or
procedural macro is not marked reviewed, or a backend-selecting cfg is set through RUSTFLAGS or a
Cargo config file.

Cargo reports each package's features once for the whole graph, not per platform, so the reviewed
feature lists are what `cargo metadata` prints, which can be a superset of what one target compiles.

`--write` regenerates the allowlist from the current metadata: new or changed build-time packages are
written as not reviewed, and the member dependency lists are kept (only created when the file is
missing). Standard library only.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
RUST = ROOT / "rust"
ALLOWLIST = RUST / "dependency-allowlist.json"
TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
)
CRATES_IO = {"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}
# Cfgs that select a different random-number or curve backend than the reviewed default.
FORBIDDEN_CFGS = ("getrandom_backend", "curve25519_dalek_backend", "curve25519_dalek_bits")


def cargo_command():
    channel = tomllib.loads((RUST / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    return ["rustup", "run", channel, "cargo"] if shutil.which("rustup") else ["cargo"]


def run_metadata(target):
    command = cargo_command() + ["metadata", "--locked", "--format-version", "1",
                                 "--manifest-path", str(RUST / "Cargo.toml"), "--filter-platform", target]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"cargo metadata failed for {target}:\n{result.stderr.strip()}")
    return json.loads(result.stdout)


def snapshot(metadata):
    """Reduce cargo metadata to the facts the checks need.

    Returns (members, packages): members maps a workspace member to the sorted names of its direct
    dependencies of every kind; packages maps "name version" to the other resolved packages' data.
    """
    by_id = {package["id"]: package for package in metadata["packages"]}
    member_ids = set(metadata["workspace_members"])
    members = {by_id[i]["name"]: sorted({d["name"] for d in by_id[i]["dependencies"]}) for i in member_ids}
    packages = {}
    for node in metadata["resolve"]["nodes"]:
        if node["id"] in member_ids:
            continue
        package = by_id[node["id"]]
        kinds = {"custom-build": "build-script", "proc-macro": "proc-macro"}
        build_time = sorted({kinds[k] for t in package["targets"] for k in t["kind"] if k in kinds})
        packages[f"{package['name']} {package['version']}"] = {
            "features": sorted(node["features"]), "source": package["source"], "build_time": build_time}
    return members, packages


def check_members(members, allowlist):
    problems = []
    allowed = allowlist["members"]
    for name in sorted(set(members) | set(allowed)):
        if name not in allowed:
            problems.append(f"unexpected workspace member {name}")
        elif name not in members:
            problems.append(f"workspace member {name} is missing")
        elif members[name] != sorted(allowed[name]):
            problems.append(f"{name}: direct dependencies differ from the allowlist" + diff_lines(
                sorted(allowed[name]), members[name]))
    return problems


def diff_lines(expected, actual):
    """Render a readable difference: '+' is present now but not reviewed, '-' is reviewed but gone."""
    extra = [f"\n    + {item}" for item in actual if item not in expected]
    missing = [f"\n    - {item}" for item in expected if item not in actual]
    return "".join(extra + missing)


def check_packages(packages, expected):
    if sorted(packages) == sorted(expected):
        return []
    return ["resolved package set differs from the reviewed list" + diff_lines(sorted(expected), sorted(packages))]


def check_features(packages, expected):
    problems = []
    for key in sorted(set(packages) & set(expected)):
        reviewed = sorted(filter(None, expected[key].split(",")))
        if packages[key]["features"] != reviewed:
            problems.append(f"{key}: enabled features differ from the reviewed list" + diff_lines(
                reviewed, packages[key]["features"]))
    return problems


def check_sources(packages):
    return [f"{key} comes from {package['source'] or 'a path'}, not crates.io"
            for key, package in sorted(packages.items()) if package["source"] not in CRATES_IO]


def check_build_time(packages, reviewed):
    problems = []
    for key, package in sorted(packages.items()):
        if not package["build_time"]:
            continue
        entry = reviewed.get(key)
        kinds = " and ".join(package["build_time"])
        if entry is None:
            problems.append(f"{key} has {kinds} but is not in the allowlist's build_time_code table")
        elif entry["kinds"] != package["build_time"]:
            problems.append(f"{key}: build-time code is {kinds}, the allowlist says {' and '.join(entry['kinds'])}")
        elif entry["build_time_code_reviewed"] is not True:
            problems.append(f"{key} has {kinds} that has not been reviewed (build_time_code_reviewed is not true)")
    return problems


def check_build_config(environment, config_texts):
    """environment: variable name to value; config_texts: path to the text of a Cargo config file."""
    problems = []
    for name, value in sorted(environment.items()):
        if name.endswith("RUSTFLAGS"):
            problems += [f"environment variable {name} sets {cfg}" for cfg in FORBIDDEN_CFGS if cfg in value]
    for path, text in sorted(config_texts.items()):
        problems += [f"Cargo config {path} sets {cfg}" for cfg in FORBIDDEN_CFGS if cfg in text]
    return problems


def cargo_config_texts():
    """Every Cargo config file that applies to rust/: its directory chain up to the root, then CARGO_HOME."""
    directories = [parent / ".cargo" for parent in (RUST, *RUST.parents)]
    directories.append(Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo"))
    texts = {}
    for directory in directories:
        for name in ("config.toml", "config"):
            path = directory / name
            if path.is_file():
                texts[str(path)] = path.read_text(encoding="utf-8", errors="replace")
    return texts


def check_target(target, metadata, allowlist):
    members, packages = snapshot(metadata)
    expected = allowlist["targets"].get(target)
    if expected is None:
        return [f"no reviewed package list for {target}"]
    return (check_members(members, allowlist) + check_packages(packages, expected)
            + check_features(packages, expected) + check_sources(packages))


def generate(snapshots, previous):
    """Build an allowlist from {target: (members, packages)}."""
    old_review = previous.get("build_time_code", {})
    build_time = {}
    for _, packages in snapshots.values():
        for key, package in packages.items():
            if package["build_time"]:
                was = old_review.get(key, {})
                reviewed = was.get("build_time_code_reviewed") is True and was.get("kinds") == package["build_time"]
                build_time[key] = {"kinds": package["build_time"], "build_time_code_reviewed": reviewed}
    first_members = next(iter(snapshots.values()))[0]
    return {
        "schema_version": 1,
        "members": previous.get("members", first_members),
        "build_time_code": dict(sorted(build_time.items())),
        "targets": {target: {key: ",".join(package["features"]) for key, package in sorted(packages.items())}
                    for target, (_, packages) in snapshots.items()},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--allowlist", type=Path, default=ALLOWLIST)
    parser.add_argument("--write", action="store_true", help="regenerate the allowlist from cargo metadata")
    args = parser.parse_args(argv)
    metadata = {target: run_metadata(target) for target in TARGETS}
    if args.write:
        previous = json.loads(args.allowlist.read_text()) if args.allowlist.exists() else {}
        generated = generate({t: snapshot(m) for t, m in metadata.items()}, previous)
        args.allowlist.write_text(json.dumps(generated, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.allowlist}")
        return 0
    allowlist = json.loads(args.allowlist.read_text(encoding="utf-8"))
    problems = [("build configuration", check_build_config(dict(os.environ), cargo_config_texts()))]
    problems += [(target, check_target(target, metadata[target], allowlist)) for target in TARGETS]
    every_package = {key: package for m in metadata.values() for key, package in snapshot(m)[1].items()}
    problems.append(("build-time code", check_build_time(every_package, allowlist["build_time_code"])))
    failed = False
    for scope, found in problems:
        for problem in dict.fromkeys(found):
            failed = True
            print(f"{scope}: {problem}", file=sys.stderr)
    if failed:
        print("dependency check failed", file=sys.stderr)
        return 1
    print(f"dependency check passed for {len(TARGETS)} targets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
