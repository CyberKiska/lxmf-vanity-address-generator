# Conformance suite

A language-neutral test runner for the `lxmf-vanity` command-line tool. It treats the program as a black box, uses only the Python standard library (3.14 or newer), and runs in two modes:

- **Single mode** checks each case's expectations against one binary.
- **Differential mode** runs every case against a reference binary and a candidate binary, checks both against the case's expectations, and compares their normalized observations.

## Running

Run from the repository root, with Python in isolated mode:

```bash
python3 -I conformance/run.py --binary ./lxmf-vanity
```

```bash
python3 -I conformance/run.py --binary ./candidate --reference ./reference
```

| Option | Meaning |
|---|---|
| `--binary PATH` | The binary under test (the candidate). Required, except with `--list`. |
| `--reference PATH` | A second binary. Its presence selects differential mode. The same path as `--binary` gives a self-differential run. |
| `--cases GLOB ...` | Only cases whose id matches a glob, for example `'smoke.*'`. May be repeated. |
| `--tag TAG` | Only cases that carry this tag. May be repeated: a case matches when it carries any of the given tags. Combines with `--cases` (both must match). |
| `--exclude-tag TAG` | Leave out cases that carry this tag. May be repeated: a case is left out when it carries any of the given tags. |
| `--list` | Print the selected case ids and exit. |
| `--report FILE.json` | Write a JSON report: id, status, exit code, failures, notes and the normalized observations of each case. It never contains private keys or sidecar contents. |
| `--keep-failed DIR` | Keep the working directories of failed cases under `DIR/<case id>/<candidate or reference>`. `DIR` must be outside the repository. They may hold disposable identities. |
| `--timeout SECONDS` | Timeout for cases that set none (default 30). A timed-out process is killed and the case fails. |

Output is one line per case (`PASS`, `FAIL`, `SKIP`, `DEVIATION <id>`) followed by a summary. The exit status is 0 when every selected case passes (deviations and skips do not fail), 1 when any case fails, and 2 on a usage error.

The harness unit tests use a fake program written in Python, so they need no real binary:

```bash
python3 -m unittest discover -p '*_test.py'
```

## Continuous integration

`.github/workflows/build-binaries.yml` runs the suite in single mode on the five native targets (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, windows/arm64), with the job's read-only `contents` permission, no secrets and no cache.

- **Current build.** The `smoke` job, after it has verified the digest of the downloaded artifact and run `scripts/smoke_artifact.py`, executes only that artifact:
  - `python -I conformance/run.py --binary <artifact> --exclude-tag slow --report conformance-<os>-<arch>.json` runs every case except the `slow` ones;
  - a second step runs `--tag slow` (the signal and stream cases) and may repeat the whole set once, writing `conformance-slow-<os>-<arch>-attempt-<n>.json`. Cases that are not for the platform report `SKIP`: on Windows the slow cases skip themselves.
  - The reports are uploaded as the artifact `conformance-<os>-<arch>`. They hold no private key, identity file or sidecar contents.
- **Pinned v1 reference.** The `pinned-reference` job, which does not run on pull requests from forks, downloads this target's release asset named in `conformance/reference.json` from the repository's own `releases/download/<tag>/` URL, checks its `sha256` against that file, and runs the same two steps against those bytes (reports `conformance-pinned-*`). While `conformance/reference.json` does not exist, the job reports a notice (`Pinned v1 reference skipped`) and a step summary instead of running.

To reproduce the first step locally, put a binary where CI would, and run the command above from the repository root. `python3 -m unittest workflow_test` checks the workflow's privileges and runs the download logic against a local release directory.

## How a case runs

- Each run gets a fresh temporary directory (mode 0700 on Unix) outside the repository, used as the working directory and removed afterwards.
- The environment is empty except for `PATH` (and `SystemRoot`, `TEMP`, `TMP` on Windows), plus the case's own `env`. `GODEBUG`, `GOMAXPROCS`, `HOME` and every `LXMF_*` variable stay unset unless the case sets them.
- Standard input is closed and empty unless the case supplies bytes.
- No shell is used, and nothing touches the network.
- The harness records the exit code, the raw stdout and stderr bytes, the JSON result (when stdout is exactly one JSON object and a newline), and the files the run created, with sizes and (on Unix) permission bits. Files that existed before the run must stay unchanged.

## Writing cases

A case module in `conformance/cases/` exposes `CASES`, a list of `harness.Case`; register the module name in `MODULES` in `conformance/cases/__init__.py`. See `cases/smoke.py` for a minimal example.

- `args` may use `{tmp}` (the working directory), `{fixture:NAME}` (a path registered by `ctx.add_fixture`) and `{sep}` (the path separator).
- `setup(ctx)` can create files, directories, FIFOs and symlinks with `ctx.write`, `ctx.mkdir` or plain `os` calls on `ctx.tmp`. Raise `harness.SkipCase("reason")` to skip, for example when running as root.
- `expect` is an `Expectation` (exit code, stdout, stderr, JSON fields, created files, and a `check(ctx, observation)` hook). In expectations, paths appear as `{tmp}`.
- `compare` selects what differential mode compares: `exit`, `json`, `files`, `stderr_markers` (the default), and optionally `stdout`, `stdout_exact`, `stderr` and `sidecars`.
- `deviation` and `deviation_expect` describe a registered, allowed difference of the candidate. The candidate may then meet `deviation_expect` instead of `expect` and the case reports `DEVIATION <id>`.
- `harness.inspect_with(binary, path)` runs `--inspect PATH --json` and returns the public fields, for checking one binary's files with the other binary (`ctx.target` and `ctx.peer`).

## Normalization

Before comparison, `elapsed_seconds` (which must be a number of at least 0) and `version` are masked (a differing `version` text is only noted: both sides must carry a non-empty string; when both print one JSON object, differential `stdout` and `stdout_exact` comparisons also leave out the bytes of that top-level value, and nothing else); `attempts` is masked only for cases marked nondeterministic; identity fields are masked only for cases with random identities, but are always checked to be lowercase hex of the right length with `public_key` equal to `x25519_public + ed25519_public`. Temporary-directory prefixes become `{tmp}`. JSON must have the same keys in the same order; numbers compare by value (`0` equals `0.0`, with a note when the text differs).

## Secret scanning

The harness collects secrets from fixtures and from every 64-byte identity file the binary creates. It scans stdout, stderr, the JSON and created `*.txt` sidecars for their hex, Base64, URL-safe Base64 and Base32 forms, at any alignment, and also for each 32-byte half. A hit fails the case with `secret encoding found in <stream>`; secret values are never printed. A case that tests `--include-private-exports` may allow them in the sidecar only (`allow_sidecar_exports=True`).

## Platforms

Cases mark `platforms` as a set of `linux`, `darwin` and `windows`. On Windows, permission bits are reported as not applicable, and `.exe` is added to a binary path when needed.
