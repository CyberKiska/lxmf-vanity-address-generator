"""GODEBUG fips140 cases: every parsing rule, for six commands each.

The Go runtime reads GODEBUG before main. The rightmost fips140 key wins, the value is cut at the
first '#', nothing is trimmed, and a segment without '=' is ignored. Go's `only` mode refuses
X25519, so the tool's self-test fails (exit 1) before any file access. Cases run only the six
commands below; none can write a file (files={}).

Go accepts `on` and `debug` and then runs normally; the Rust port refuses them (deviation
DEV-fips-on-debug). Go panics on an unknown value; the Rust port prints a diagnostic and exits 2
(DEV-fips-unknown). Those unknown-value cases are in PENDING_UNKNOWN_VALUE, not CASES: the harness
fails any run whose stderr has a Go panic line, even for a declared deviation.
"""

from conformance.cases.cli_grammar import EMPTY_ARRAYS, JSON_KEYS, NO_FILES, VERSION_RE
from conformance.harness import Case, Expectation

ONLY_PREFIX = "self-test failed: X25519 public-key derivation unavailable"
ONLY_FULL = ONLY_PREFIX + ": crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode"
FAILED_KEYS = (*JSON_KEYS, "error")
ON_DEBUG = "DEV-fips-on-debug"
UNKNOWN = "DEV-fips-unknown"
MISSING = "no-such-file"  # relative to the case's empty working directory


def _error_starts_with_self_test(ctx, obs):
    error = (obs.json or {}).get("error")
    if isinstance(error, str) and error.startswith(ONLY_PREFIX):
        return []
    return [f"JSON error does not start with {ONLY_PREFIX!r}"]


def _error_is_not_self_test(ctx, obs):
    error = (obs.json or {}).get("error")
    return [] if isinstance(error, str) and error and not error.startswith("self-test failed") else ["JSON error is missing or is a self-test failure"]


# What each command does when FIPS is off or ignored. help and nope are looser than the grammar
# cases so that `debug` (extra self-test lines on stderr) still matches.
COMMANDS = {
    "version": ("--version",),
    "help": ("--help",),
    "nope": ("--nope",),
    "benchmark": ("--benchmark", "1ms", "--json"),
    "dry_run": ("--prefix", "a", "--dry-run", "--json"),
    "inspect_missing": ("--inspect", MISSING, "--json"),
}
NORMAL = {
    "version": Expectation(exit_code=0, stdout_regex=VERSION_RE, files=NO_FILES),
    "help": Expectation(exit_code=0, stdout=b"", stderr_regex=r"^Usage of lxmf-vanity:$", files=NO_FILES),
    "nope": Expectation(exit_code=2, stdout=b"", stderr_regex=r"^Error: flag provided but not defined: -nope$", files=NO_FILES),
    "benchmark": Expectation(exit_code=0, files=NO_FILES, json_keys=JSON_KEYS, json={"status": "benchmark", **EMPTY_ARRAYS, "generator": "segmented"}),
    "dry_run": Expectation(exit_code=0, files=NO_FILES, json={"status": "dry-run", **EMPTY_ARRAYS, "generator": "segmented"}),
    # The error text of a missing file belongs to the inspection cases; here it only must not be a FIPS failure.
    "inspect_missing": Expectation(exit_code=1, files=NO_FILES, json={"status": "failed", "attempts": 0}, check=_error_is_not_self_test),
}
# Exit 1 with a failed JSON result and zero attempts: all the Rust port promises when it refuses.
REFUSED = Expectation(exit_code=1, files=NO_FILES, json={"status": "failed", "attempts": 0})
ONLY_FAILED = Expectation(
    exit_code=1, files=NO_FILES, json_keys=FAILED_KEYS, check=_error_starts_with_self_test,
    json={"status": "failed", **EMPTY_ARRAYS, "attempts": 0, "generator": "segmented"},
    stderr_regex=r"^Error: " + ONLY_PREFIX)
USAGE_UNAFFECTED = ("version", "help", "nope")  # parsed before any search runs: FIPS cannot change them
# The refusal text after the first colon may differ, so compare only the outcome.
OUTCOME = frozenset({"exit", "files"})

# GODEBUG text -> how the Go binary behaves.
SETTINGS = (  # (name, GODEBUG or None, mode)
    ("unset", None, "off"),
    ("off", "fips140=off", "off"),
    ("empty_value", "fips140=", "off"),
    ("on", "fips140=on", "on"),
    ("debug", "fips140=debug", "debug"),
    ("only", "fips140=only", "only"),
    ("on_then_only", "fips140=on,fips140=only", "only"),
    ("other_key_then_only", "x=1,fips140=only", "only"),
    ("only_then_other_key", "fips140=only,x=1", "only"),
    ("only_then_off", "fips140=only,fips140=off", "off"),
    ("off_then_only", "fips140=off,fips140=only", "only"),
    ("only_then_empty", "fips140=only,fips140=", "off"),
    ("empty_then_only", "fips140=,fips140=only", "only"),
    ("only_with_comment", "fips140=only#x", "only"),
    ("off_comment_then_only", "fips140=off#x,fips140=only", "only"),
    ("on_with_comment_naming_only", "fips140=on#only", "on"),
    ("key_without_value", "fips140", "off"),
    ("empty_key_then_off", "=only,fips140=off", "off"),
    ("trailing_comma", "fips140=only,", "only"),
    ("key_with_space", "fips140 =only", "off"),
    ("key_in_capitals", "FIPS140=only", "off"),
    ("unknown_then_off", "fips140=bogus,fips140=off", "off"),  # the rightmost value wins, so the unknown one is never read
)
# Go panics before main on these; see PENDING_UNKNOWN_VALUE.
UNKNOWN_SETTINGS = (
    ("bogus", "fips140=bogus"),
    ("capital_only", "fips140=ONLY"),
    ("trailing_space", "fips140=only "),
    ("after_valid", "fips140=off,fips140=bogus"),
)


def _case(name, setting, command, expect, masked=False, **kw):
    """masked: the run is a normal search, so its attempts and identity differ between runs."""
    args = COMMANDS[command]
    return Case(id=f"fips.{name}.{command}", args=args, env={} if setting is None else {"GODEBUG": setting}, expect=expect,
                description=kw.pop("description", f"GODEBUG={setting!r} {' '.join(args)}"),
                random_identity=masked and command == "dry_run", attempts_nondeterministic=masked and command in ("benchmark", "dry_run"), **kw)


CASES = []
for name, setting, mode in SETTINGS:
    for command in COMMANDS:
        normal = NORMAL[command]
        if mode == "off" or command in USAGE_UNAFFECTED:
            CASES.append(_case(name, setting, command, normal, masked=True))
        elif mode == "only":
            CASES.append(_case(name, setting, command, ONLY_FAILED, compare=OUTCOME,
                               description=f"GODEBUG={setting!r}: {' '.join(COMMANDS[command])} fails the self-test (exit 1, 0 attempts, no files)"))
        else:  # on, debug: Go runs normally; the Rust port refuses everything that is not help, version or a usage error
            CASES.append(_case(name, setting, command, normal, deviation=ON_DEBUG, deviation_expect=REFUSED, compare=OUTCOME))

PENDING_UNKNOWN_VALUE = []
for name, setting in UNKNOWN_SETTINGS:
    for command in COMMANDS:
        # Go: runtime panic before main, exit 2, nothing on stdout. Rust: a diagnostic, exit 2, nothing on stdout, for every command.
        go = Expectation(exit_code=2, stdout=b"", files=NO_FILES, stderr_contains=("unknown GODEBUG setting",))
        rust = Expectation(exit_code=2, stdout=b"", files=NO_FILES)
        PENDING_UNKNOWN_VALUE.append(_case(f"unknown_{name}", setting, command, go, deviation=UNKNOWN, deviation_expect=rust, compare=OUTCOME))
