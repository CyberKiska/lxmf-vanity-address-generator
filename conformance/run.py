#!/usr/bin/env python3
"""Run the lxmf-vanity conformance cases against one binary, or compare two binaries.

    python3 -I conformance/run.py --binary PATH [--reference PATH] [--cases GLOB ...]
                                  [--tag TAG ...] [--exclude-tag TAG ...] [--list] [--report FILE.json]
                                  [--keep-failed DIR] [--timeout SECONDS]

Exit status: 0 when every selected case passes, 1 when any fails, 2 on a usage error.
"""

import argparse
import json
import os
from pathlib import Path
import sys

# -I removes the script directory from sys.path: add the repository root for the package import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from conformance import harness  # noqa: E402
from conformance.cases import load_cases  # noqa: E402


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="run.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", help="the binary under test (the candidate)")
    parser.add_argument("--reference", help="reference binary: run in differential mode")
    parser.add_argument("--cases", nargs="+", action="append", default=[], metavar="GLOB",
                        help="only cases whose id matches a glob, for example 'smoke.*'")
    parser.add_argument("--tag", action="append", default=[], metavar="TAG",
                        help="only cases that carry this tag (repeatable: any of the tags)")
    parser.add_argument("--exclude-tag", action="append", default=[], metavar="TAG",
                        help="leave out cases that carry this tag (repeatable: any of the tags)")
    parser.add_argument("--list", action="store_true", help="list the selected cases and exit")
    parser.add_argument("--report", metavar="FILE.json", help="write a JSON report (no secrets)")
    parser.add_argument("--keep-failed", metavar="DIR", help="keep the working directories of failed cases here")
    parser.add_argument("--timeout", type=float, default=harness.DEFAULT_TIMEOUT, metavar="SECONDS",
                        help="timeout for cases that set none (default %(default)s)")
    args = parser.parse_args(argv)
    if not args.list and not args.binary:
        parser.error("--binary is required")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def select(cases, args):
    """Cases that match --cases, carry one of --tag (when given) and carry none of --exclude-tag."""
    selected = harness.select_cases(cases, [g for group in args.cases for g in group])
    return [c for c in selected
            if (not args.tag or c.tags & set(args.tag)) and not c.tags & set(args.exclude_tag)]


def describe(result):
    if result.status == "DEVIATION":
        head = f"DEVIATION {result.deviation} {result.id}"
    elif result.status == "FAIL" and result.failures and result.failures[0].startswith(("(timeout)", "candidate: (timeout)")):
        head = f"FAIL {result.id} (timeout)"
    else:
        head = f"{result.status} {result.id}"
    lines = [head]
    lines += [f"    {text}" for text in result.failures]
    lines += [f"    note: {text}" for text in result.notes]
    return "\n".join(lines)


def main(argv=None, cases=None):
    args = parse_args(argv)
    cases = load_cases() if cases is None else cases
    selected = select(cases, args)
    if args.list:
        for case in selected:
            print(f"{case.id}\t{case.description}")
        return 0
    if not selected:
        print("error: no cases match", file=sys.stderr)
        return 2
    try:
        target = harness.Target.from_path(args.binary)
        reference = harness.Target.from_path(args.reference) if args.reference else None
        if args.keep_failed:
            if harness._inside(args.keep_failed, harness.REPO_ROOT):
                raise harness.HarnessError("--keep-failed must be outside the repository")
            Path(args.keep_failed).mkdir(parents=True, exist_ok=True)
    except (harness.HarnessError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    mode = "differential" if reference else "single"
    print(f"mode: {mode}; binary: {target.label}" + (f"; reference: {reference.label}" if reference else ""))
    results = []
    for case in selected:
        result = harness.run_case(case, target, reference, default_timeout=args.timeout,
                                  keep_failed=args.keep_failed)
        results.append(result)
        print(describe(result), flush=True)
    counts = {s: sum(r.status == s for r in results) for s in ("PASS", "FAIL", "SKIP", "DEVIATION")}
    print(f"summary: {len(results)} cases, {counts['PASS']} passed, {counts['FAIL']} failed, "
          f"{counts['SKIP']} skipped, {counts['DEVIATION']} deviations")
    if args.report:
        report = harness.build_report(results, mode, target.label, reference.label if reference else None)
        try:
            Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write the report: {exc.strerror}", file=sys.stderr)
            return 2
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
