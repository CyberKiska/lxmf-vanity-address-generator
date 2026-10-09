#!/usr/bin/env python3
"""Execute verified downloaded artifacts in disposable output directories."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


DIRECTORY_SYNC_LIMIT = "directory sync unsupported on this filesystem; power-loss durability is not verified"


def check_generation(result, target_os, path):
    saved = json.loads(result.stdout)
    if result.returncode != 0 or saved["status"] != "saved":
        raise ValueError(f"artifact generation failed (status {result.returncode})")
    if saved["deviations"] or saved["unverified_files"]:
        raise ValueError("artifact generation reported deviations")
    if saved["verified_files"] != [str(path)]:
        raise ValueError("artifact did not verify the requested identity file")
    # Go cannot flush a directory on Windows; that is a platform notice only.
    allowed = {DIRECTORY_SYNC_LIMIT} if target_os == "windows" else set()
    if not set(saved["notices"]) <= allowed:
        raise ValueError("artifact generation reported unexpected notices")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    target_os = os.environ["TARGET_OS"]
    target_arch = os.environ["TARGET_ARCH"]
    suffix = ".exe" if target_os == "windows" else ""
    binary = (args.directory / f"lxmf-vanity-{target_os}-{target_arch}{suffix}").resolve()
    digest, filename = Path(str(binary) + ".sha256").read_text().split()
    if filename != binary.name or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError("downloaded artifact checksum mismatch")
    if target_os != "windows":
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    version = subprocess.run([str(binary), "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout
    if os.environ["EXPECTED_VERSION"] not in version or f"{target_os}/{target_arch}" not in version:
        raise ValueError("artifact version/target mismatch")
    subprocess.run([str(binary), "--benchmark", "1s", "--workers", "1"], check=True, timeout=15)
    with tempfile.TemporaryDirectory(prefix="lxmf-smoke-") as directory:
        path = Path(directory) / "saved"
        command = [str(binary), "--prefix", "0", "--workers", "1", "--out", str(path), "--json"]
        if target_os == "windows":
            command.append("--allow-weak-output-protection")
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        check_generation(result, target_os, path)
        if path.stat().st_size != 64 or not Path(str(path) + ".txt").is_file():
            raise ValueError("artifact did not save identity and metadata")
        inspected = subprocess.run([str(binary), "--inspect", str(path)], check=True,
                                   capture_output=True, text=True, timeout=15).stdout
        metadata = Path(str(path) + ".txt").read_text()
        for label in ("Address (LXMF)", "Identity Hash", "Combined"):
            field = next(line for line in inspected.splitlines() if line.strip().startswith(label + ":"))
            if field not in metadata:
                raise ValueError("artifact inspection differs from saved metadata")
    print(f"Verified and executed {binary.name}: {version.strip()}")


if __name__ == "__main__":
    main()
