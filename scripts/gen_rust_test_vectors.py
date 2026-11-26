#!/usr/bin/env python3
"""Convert the JSON identity fixtures into the line formats the Rust tests read.

The Rust crates have no JSON parser (they use only the standard library), so this script turns the
two public fixtures in testdata/ into plain text under rust/core/tests/data/:

  rns-identity-vectors.txt   `message <hex of UTF-8>` and `peer_private <hex>` header lines, then one
                             line per vector: raw private public hash address signature shared
                             (space-separated lowercase hex).
  rns-1.4.2-golden.txt       one `key value` line per JSON key, sorted by key; booleans are
                             `true`/`false`.

The output is deterministic and uses `\\n` line endings. `--check` writes nothing and exits 1 when a
file is missing or stale. Standard library only.
"""

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "testdata"
OUTPUT = ROOT / "rust" / "core" / "tests" / "data"

# Vector fields in line order, with their length in bytes.
VECTOR_FIELDS = (("raw", 64), ("private", 64), ("public", 64), ("hash", 16), ("address", 16),
                 ("signature", 64), ("shared", 32))
HEX = re.compile(r"[0-9a-f]*")


def check_hex(name, value, size=None):
    if not isinstance(value, str) or not HEX.fullmatch(value) or len(value) % 2:
        raise ValueError(f"{name} is not lowercase hexadecimal")
    if size is not None and len(value) != 2 * size:
        raise ValueError(f"{name} must be {size} bytes")
    return value


def convert_vectors(document):
    """Return the text of rns-identity-vectors.txt for the parsed JSON document."""
    message = document["message"]
    if not isinstance(message, str) or not message:
        raise ValueError("message must be a non-empty string")
    lines = [f"message {message.encode('utf-8').hex()}",
             f"peer_private {check_hex('peer_private', document['peer_private'], 32)}"]
    for index, vector in enumerate(document["vectors"]):
        lines.append(" ".join(check_hex(f"vector {index} {name}", vector[name], size)
                              for name, size in VECTOR_FIELDS))
    return "\n".join(lines) + "\n"


def convert_golden(document):
    """Return the text of rns-1.4.2-golden.txt for the parsed JSON document."""
    lines = []
    for key in sorted(document):
        value = document[key]
        if isinstance(value, bool):
            text = "true" if value else "false"
        elif isinstance(value, str) and re.fullmatch(r"[0-9A-Za-z.]+", value):
            text = value
        else:
            raise ValueError(f"{key} has an unsupported value")
        if not re.fullmatch(r"[a-z0-9_]+", key):
            raise ValueError(f"{key} is not a plain key")
        lines.append(f"{key} {text}")
    return "\n".join(lines) + "\n"


def outputs(sources=SOURCES):
    """Map output file name to its expected content."""
    vectors = json.loads((sources / "rns-identity-vectors.json").read_text(encoding="utf-8"))
    golden = json.loads((sources / "rns-1.4.2-golden.json").read_text(encoding="utf-8"))
    return {"rns-identity-vectors.txt": convert_vectors(vectors),
            "rns-1.4.2-golden.txt": convert_golden(golden)}


def stale(expected, target=OUTPUT):
    """Return the names of the files whose content differs from `expected`."""
    result = []
    for name, text in expected.items():
        path = target / name
        if not path.is_file() or path.read_bytes() != text.encode("utf-8"):
            result.append(name)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the generated files are stale")
    parser.add_argument("--sources", type=Path, default=SOURCES, help=argparse.SUPPRESS)
    parser.add_argument("--target", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        expected = outputs(args.sources)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"gen_rust_test_vectors: {error}", file=sys.stderr)
        return 2
    if args.check:
        names = stale(expected, args.target)
        for name in names:
            print(f"stale: {name}; run scripts/gen_rust_test_vectors.py", file=sys.stderr)
        return 1 if names else 0
    args.target.mkdir(parents=True, exist_ok=True)
    for name, text in expected.items():
        (args.target / name).write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
