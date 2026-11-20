"""Three trivial cases that prove the harness works end to end."""

from conformance.harness import Case, Expectation

JSON_KEYS = ("status", "verified_files", "unverified_files", "deviations", "notices",
             "attempts", "elapsed_seconds", "generator", "version")

CASES = [
    Case(
        id="smoke.help",
        description="--help prints the usage text on stderr, nothing on stdout, and exits 0",
        args=("--help",),
        expect=Expectation(exit_code=0, stdout=b"", stderr_regex=r"\AUsage of lxmf-vanity:\n",
                           stderr_contains=("include-private-exports",), files={}),
        compare=frozenset({"exit", "stdout", "files"}),
    ),
    Case(
        id="smoke.version",
        description="--version prints one line with the version, Go or Rust version and target",
        args=("--version",),
        expect=Expectation(exit_code=0, stdout_regex=r"\Alxmf-vanity \S+ \(\S+ (linux|darwin|windows)/(amd64|arm64)\)\n\Z",
                           stderr_lines=(), files={}),
        compare=frozenset({"exit", "files", "stderr_markers"}),
    ),
    Case(
        id="smoke.version_json",
        description="--version --json prints one JSON object with status version and empty arrays",
        args=("--version", "--json"),
        expect=Expectation(
            exit_code=0, stderr_lines=(), files={}, json_keys=JSON_KEYS,
            json={"status": "version", "verified_files": [], "unverified_files": [], "deviations": [],
                  "notices": [], "attempts": 0, "generator": "segmented"}),  # elapsed_seconds and version are masked
    ),
]
