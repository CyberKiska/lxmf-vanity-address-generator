#!/usr/bin/env python3
"""Resolve current stable PyPI references and install exact wheels per run."""

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request


STABLE_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:\.post[0-9]+)?\Z")


def resolve_latest(name):
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as response:
        data = json.load(response)
    versions = [version for version, files in data["releases"].items()
                if STABLE_VERSION.fullmatch(version)
                and any(not item.get("yanked", False) for item in files)]
    if not versions:
        raise ValueError(f"{name}: no stable, non-yanked release is available")
    def order(version):
        base, _, post = version.partition(".post")
        numbers = tuple(int(n) for n in base.split("."))
        return numbers + (0,) * max(0, 8 - len(numbers)), int(post or "0")
    return max(versions, key=order)


def install(selection, report_directory):
    for name in ("rns", "lxmf"):
        if not STABLE_VERSION.fullmatch(selection[name]):
            raise ValueError("invalid recorded reference version")
    pip = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
           "--index-url", "https://pypi.org/simple", "--only-binary=:all:"]
    requirements = Path(__file__).resolve().parent.parent / "requirements-reference.txt"
    subprocess.run(pip + ["--require-hashes", "-r", str(requirements), "--report",
                          str(report_directory / "dependencies-install.json")], check=True)
    subprocess.run(pip + ["--no-deps", "--report", str(report_directory / "reference-install.json"),
                          *[f"{name}=={selection[name]}" for name in ("rns", "lxmf")]], check=True)
    subprocess.run([sys.executable, "-m", "pip", "check"], check=True)
    for name in ("rns", "lxmf"):
        if importlib.metadata.version(name) != selection[name]:
            raise ValueError(f"{name}: installed version differs from the selected latest version")
    provenance = {"selected": selection, "python": sys.version,
                  "pip": importlib.metadata.version("pip"), "wheels": []}
    for report in ("dependencies-install.json", "reference-install.json"):
        for entry in json.loads((report_directory / report).read_text())["install"]:
            provenance["wheels"].append({"name": entry["metadata"]["name"],
                                        "version": entry["metadata"]["version"],
                                        "sha256": entry["download_info"]["archive_info"]["hashes"]["sha256"]})
    (report_directory / "reference-provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(provenance, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolve-only", action="store_true")
    parser.add_argument("--selection", type=Path, default=Path("reference-selection.json"))
    parser.add_argument("--report-directory", type=Path, default=Path("."))
    args = parser.parse_args()
    if args.resolve_only:
        selection = {name: resolve_latest(name) for name in ("rns", "lxmf")}
        args.selection.write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                for name, version in selection.items():
                    output.write(f"{name}={version}\n")
        print(json.dumps(selection))
    else:
        install(json.loads(args.selection.read_text()), args.report_directory)


if __name__ == "__main__":
    main()
