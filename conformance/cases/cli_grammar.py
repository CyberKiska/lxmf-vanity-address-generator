"""Command-line grammar, help and version cases.

Every case observes parsing through runs that write nothing: --benchmark with a tiny duration,
--dry-run capped at a few attempts (an 8-hex-digit pattern cannot match in 3 attempts), --version,
--help, or --inspect of the public 00..3f fixture. Every expectation lists files={} so a case
fails if the tool creates anything. Helpers at the top are reused by cli_validation and fips.
"""

import re

from conformance.harness import Case, Expectation

NO_FILES = {}
FIXTURE = "golden-public-fixture"  # 64 bytes 00..3f, the public known-answer input
GOLDEN_ADDRESS = "fae321c442e3c9bdcd7a3e79d850e03c"
VERSION_RE = r"\Alxmf-vanity \S+ \(\S+ (linux|darwin|windows)/(amd64|arm64)\)\n\Z"
NON_WINDOWS = frozenset({"linux", "darwin"})
WINDOWS = frozenset({"windows"})
JSON_KEYS = ("status", "verified_files", "unverified_files", "deviations", "notices", "attempts",
             "elapsed_seconds", "generator", "version")
EMPTY_ARRAYS = {"verified_files": [], "unverified_files": [], "deviations": [], "notices": []}
BENCH = ("--benchmark", "1ms", "--workers", "1")
CAP = ("--dry-run", "--workers", "1", "--max-attempts", "3")  # with prefix ffffffff: exit 4 after 3 attempts
WORKERS_DEFAULT_DEVIATION = "DEV-workers-default"


def setup_golden(ctx):
    ctx.write(FIXTURE, bytes(range(64)))


# --- Usage text (REFERENCE_FACTS 3) --------------------------------------------

_FLAGS = (  # (name, type label, description), in the order Go prints them
    ("allow-inherited-windows-acl", None, "On Windows, explicitly accept the output directory's inherited ACL for private files"),
    ("allow-weak-output-protection", None, "Explicitly accept failed/unavailable output protection checks"),
    ("benchmark", "duration", "Benchmark full identity generation for a duration (for example 30s); no identity is selected or saved"),
    ("dry-run", None, "Find a match but do not save it"),
    ("fallback-out", "string", "Preflighted secondary identity file for save recovery"),
    ("generator", "string", 'Candidate generator: segmented or independent (default "segmented")'),
    ("include-private-exports", None, "Include reversible private-key exports in <out>.txt (sensitive)"),
    ("inspect", "string", "Print public metadata for a 64-byte identity; write nothing"),
    ("json", None, "Write one public JSON result to stdout"),
    ("max-attempts", "uint", "Maximum reserved candidates; 0 is unlimited"),
    ("out", "string", 'Output path for identity file (default "identity")'),
    ("postfix", "string", "Desired hex postfix/suffix (1-32 chars)"),
    ("prefix", "string", "Desired hex prefix (1-32 chars)"),
    ("save-retry-timeout", "duration", "Save recovery deadline; 0 retries indefinitely (cannot interrupt blocked I/O)"),
    ("timeout", "duration", "Search timeout; 0 is unlimited (does not limit saving)"),
    ("version", None, "Print version, Go version and target without searching"),
    ("workers", "int", "Number of parallel workers (default @W@)"),
)


def usage_lines(workers):
    lines = ["Usage of lxmf-vanity:"]
    for name, kind, text in _FLAGS:
        lines += [f"  -{name}" + (f" {kind}" if kind else ""), "    \t" + text.replace("@W@", str(workers))]
    return lines


# Any default worker count: it follows the machine, not the input.
USAGE_RE = re.escape("\n".join(usage_lines("WORKERSDEFAULT")) + "\n").replace("WORKERSDEFAULT", r"\d+")


# --- Expectation builders ---------------------------------------------------------

def parse_error(message):
    """Exit 2 from the flag parser: message, the usage text, then the Error line; stdout empty."""
    return Expectation(exit_code=2, stdout=b"", files=NO_FILES,
                       stderr_regex=r"\A" + re.escape(message) + r"\n" + USAGE_RE + "Error: " + re.escape(message) + r"\n\Z")


def validation_error(message):
    """Exit 2 from validation: exactly one stderr line, nothing on stdout."""
    return Expectation(exit_code=2, stdout=b"", stderr_lines=(f"Error: {message}",), files=NO_FILES)


def positional_error(quoted):
    return validation_error(f"unexpected positional arguments {quoted}; all options must use flags")


def bench_ok(workers=1, generator="segmented"):
    banner = rf'^LXMF vanity search: prefix="" postfix="" workers={workers}$\n^Generator: {re.escape(generator)}$'
    return Expectation(
        exit_code=0, files=NO_FILES, stderr_regex=banner, stderr_contains=("search started",),
        stdout_regex=rf"\ABenchmark complete: \S+ attempts in \S+ \(\S+/s average\), generator={re.escape(generator)}\n\Z")


def bench_json(generator="segmented"):
    return Expectation(exit_code=0, files=NO_FILES, json_keys=JSON_KEYS,
                       json={"status": "benchmark", **EMPTY_ARRAYS, "generator": generator},
                       stderr_regex=rf'^LXMF vanity search: prefix="" postfix="" workers=1$\n^Generator: {re.escape(generator)}$')


def capped(prefix="", postfix="", workers=1, generator="segmented"):
    """Dry-run stopped by --max-attempts 3 on a pattern that cannot match: exit 4, nothing saved."""
    n = len(prefix) + len(postfix)
    return Expectation(
        exit_code=4, files=NO_FILES, stdout="Search failed: search attempt limit reached\n",
        stderr_regex=rf'^LXMF vanity search: prefix="{prefix}" postfix="{postfix}" workers={workers}$',
        stderr_contains=(f"Expected attempts: {16 ** n} (geometric expectation; not a deadline)",
                         "Warning: --dry-run discards the matching private identity.", f"Generator: {generator}"))


CAPPED = capped(prefix="ffffffff")
BENCH_TEXT = bench_ok()
INSPECTED = Expectation(
    exit_code=0, files=NO_FILES, stdout_regex=rf"^Address \(LXMF\): {GOLDEN_ADDRESS}$",
    stderr_regex=r"^Warning: unmasked X25519 input; imported bytes were preserved and no file was written\.$")
VERSION_TEXT = Expectation(exit_code=0, stdout_regex=VERSION_RE, stderr_lines=(), files=NO_FILES)


def starts_with(prefix):
    def check(ctx, obs):
        address = (obs.json or {}).get("address")
        return [] if isinstance(address, str) and address.startswith(prefix) else [f"address does not start with {prefix!r}"]
    return check


def tag(index, value):
    """Unique, readable case-id segment: a running index plus the value with odd characters folded."""
    text = str(value).lower().replace("+", " plus ").replace("-", " minus ")
    return f"{index:03d}_" + (re.sub(r"[^a-z0-9]+", "_", text).strip("_") or "empty")


def case(cid, description, args, expect, **kw):
    return Case(id=f"cli_grammar.{cid}", description=description, args=tuple(args), expect=expect, **kw)


CASES = []
add = CASES.append

# --- Flag forms: -f v, --f v, -f=v, --f=v (booleans: -f, --f, -f=true, --f=true) ----------

_NONBENCH = ("--workers", "1")
SPECS = (  # (case name, flag, kind, value, other args, expectation, platforms)
    ("prefix", "prefix", "value", "ffffffff", CAP, CAPPED, None),
    ("postfix", "postfix", "value", "ffffffff", CAP, capped(postfix="ffffffff"), None),
    ("workers", "workers", "value", "2", ("--benchmark", "1ms"), bench_ok(workers=2), None),
    ("out", "out", "value", "custom-name", BENCH, BENCH_TEXT, None),
    ("dry-run", "dry-run", "bool", None, ("--prefix", "ffffffff", "--workers", "1", "--max-attempts", "3"), CAPPED, None),
    ("include-private-exports", "include-private-exports", "bool", None, BENCH,
     validation_error("--benchmark cannot be combined with --include-private-exports"), None),
    ("benchmark", "benchmark", "value", "1ms", _NONBENCH, BENCH_TEXT, None),
    ("allow-inherited-windows-acl-posix", "allow-inherited-windows-acl", "bool", None, BENCH,
     validation_error("--allow-inherited-windows-acl is only valid on Windows"), NON_WINDOWS),
    ("allow-inherited-windows-acl-windows", "allow-inherited-windows-acl", "bool", None, BENCH, BENCH_TEXT, WINDOWS),
    ("allow-weak-output-protection", "allow-weak-output-protection", "bool", None, BENCH, BENCH_TEXT, None),
    ("fallback-out", "fallback-out", "value", "fallback", BENCH, validation_error("save recovery options require saving mode"), None),
    ("save-retry-timeout", "save-retry-timeout", "value", "1s", BENCH, validation_error("save recovery options require saving mode"), None),
    ("max-attempts", "max-attempts", "value", "3", ("--prefix", "ffffffff", "--dry-run", "--workers", "1", "--json"),
     Expectation(exit_code=4, files=NO_FILES, json={"status": "limited", "attempts": 3, "error": "search attempt limit reached"}), None),
    ("timeout", "timeout", "value", "1h", ("--prefix", "ffffffff", *CAP), CAPPED, None),
    ("generator", "generator", "value", "independent", BENCH, bench_ok(generator="independent"), None),
    ("inspect", "inspect", "value", FIXTURE, (), INSPECTED, None),
    ("version", "version", "bool", None, (), VERSION_TEXT, None),
    ("json", "json", "bool", None, BENCH, bench_json(), None),
)


def forms(flag, kind, value):
    if kind == "bool":
        return (("dash", (f"-{flag}",)), ("ddash", (f"--{flag}",)),
                ("dash_eq_true", (f"-{flag}=true",)), ("ddash_eq_true", (f"--{flag}=true",)))
    return (("dash_sep", (f"-{flag}", value)), ("ddash_sep", (f"--{flag}", value)),
            ("dash_eq", (f"-{flag}={value}",)), ("ddash_eq", (f"--{flag}={value}",)))


for name, flag, kind, value, others, expect, platforms in SPECS:
    for form, given in forms(flag, kind, value):
        add(case(f"form.{name}.{form}", f"--{flag} is accepted as {given}", (*given, *others), expect,
                 setup=setup_golden if flag == "inspect" else None, platforms=platforms,
                 attempts_nondeterministic=flag == "json"))
    if platforms is WINDOWS:
        continue  # one trailing-positional case per flag is enough
    given = forms(flag, kind, value)[1][1]
    add(case(f"trailing.after_{name}", f"a positional argument after --{flag} is rejected", (*given, *others, "extra"),
             positional_error('["extra"]')))

# --- Booleans: every ParseBool spelling ---------------------------------------------------

for i, spelling in enumerate(("1", "t", "T", "TRUE", "true", "True")):
    add(case(f"bool.json_true.{tag(i, spelling)}", f"--json={spelling} is true", (*BENCH, f"--json={spelling}"),
             bench_json(), attempts_nondeterministic=True))
for i, spelling in enumerate(("0", "f", "F", "FALSE", "false", "False")):
    add(case(f"bool.json_false.{tag(i, spelling)}", f"--json={spelling} is false", (*BENCH, f"--json={spelling}"), BENCH_TEXT))
for i, spelling in enumerate(("yes", "no", "y", "n", "on", "off", "tRUE", "TRue", "fALSE", "2", "-1", "01", "00", "t1",
                              "true ", " true", "truee", "true=1", "", "\u0661")):
    add(case(f"bool.json_invalid.{tag(i, spelling)}", f"--json={spelling!r} is not a boolean", (*BENCH, f"--json={spelling}"),
             parse_error(f'invalid boolean value "{spelling}" for -json: parse error')))
for flag in ("dry-run", "include-private-exports", "allow-inherited-windows-acl", "allow-weak-output-protection", "version"):
    add(case(f"bool.{flag}.false", f"--{flag}=false switches it off", (*BENCH, f"--{flag}=false"), BENCH_TEXT))
    add(case(f"bool.{flag}.invalid", f"--{flag}=bogus is a parse error", (*BENCH, f"--{flag}=bogus"),
             parse_error(f'invalid boolean value "bogus" for -{flag}: parse error')))
    add(case(f"bool.{flag}.empty", f"--{flag}= is a parse error", (*BENCH, f"--{flag}="),
             parse_error(f'invalid boolean value "" for -{flag}: parse error')))
add(case("bool.next_argument_is_positional", "a boolean flag never consumes the next argument",
         ("--json", "false", "--benchmark", "1ms"), positional_error('["false" "--benchmark" "1ms"]')))
add(case("bool.next_argument_is_positional_true", "--dry-run true leaves true as a positional argument",
         ("--prefix", "ffffffff", "--dry-run", "true"), positional_error('["true"]')))

# --- --workers: ParseInt(s, 0, 64) -----------------------------------------------------------

WORKERS_OK = (("1", 1), ("2", 2), ("+1", 1), ("+2", 2), ("010", 8), ("0_1", 1), ("0x2", 2), ("0X2", 2), ("0o10", 8),
              ("0O10", 8), ("0b11", 3), ("0B11", 3), ("0b1_0", 2), ("0b_1", 1), ("0x_1", 1), ("1_0", 10), ("0x1_0", 16),
              ("256", 256), ("0x100", 256), ("0400", 256))
for i, (text, n) in enumerate(WORKERS_OK):
    add(case(f"workers.ok.{tag(i, text)}", f"--workers {text} means {n}", ("--benchmark", "1ms", "--workers", text), bench_ok(workers=n)))
WORKERS_RANGE = (("0", "be at least 1"), ("-1", "be at least 1"), ("-0", "be at least 1"), ("+0", "be at least 1"), ("0x0", "be at least 1"),
                 ("00", "be at least 1"), ("-9223372036854775808", "be at least 1"), ("-0x8000000000000000", "be at least 1"),
                 ("257", "not exceed 256"), ("1_000", "not exceed 256"), ("9223372036854775807", "not exceed 256"),
                 ("0x7fffffffffffffff", "not exceed 256"))
for i, (text, rule) in enumerate(WORKERS_RANGE):
    add(case(f"workers.parsed_then_rejected.{tag(i, text)}", f"--workers {text} parses and fails validation",
             ("--benchmark", "1ms", "--workers", text), validation_error(f"workers must {rule}")))
WORKERS_BAD = (("", "parse error"), ("_1", "parse error"), ("1__0", "parse error"), ("1_", "parse error"), ("0x_", "parse error"),
               ("0x", "parse error"), ("0o", "parse error"), ("0b2", "parse error"), ("09", "parse error"), ("08", "parse error"),
               ("0_8", "parse error"), ("0_x1", "parse error"), ("08_1", "parse error"), ("1.0", "parse error"),
               ("1e3", "parse error"), (" 1", "parse error"), ("1 ", "parse error"), ("-", "parse error"), ("+", "parse error"),
               ("--1", "parse error"), ("+-1", "parse error"), ("abc", "parse error"), ("\uff11", "parse error"),
               ("9223372036854775808", "value out of range"), ("-9223372036854775809", "value out of range"),
               ("0x8000000000000000", "value out of range"), ("99999999999999999999", "value out of range"))
for i, (text, why) in enumerate(WORKERS_BAD):
    add(case(f"workers.invalid.{tag(i, text)}", f"--workers {text!r} is rejected by the parser",
             ("--benchmark", "1ms", "--workers", text), parse_error(f'invalid value "{text}" for flag -workers: {why}')))

# --- --max-attempts: ParseUint(s, 0, 64) ------------------------------------------------------

ATTEMPTS_OK = (("1", 1), ("3", 3), ("0x10", 16), ("0X10", 16), ("0o17", 15), ("0O17", 15), ("0b101", 5), ("0B101", 5),
               ("010", 8), ("1_0", 10), ("0x1_0", 16), ("0_7", 7), ("31", 31))
for i, (text, n) in enumerate(ATTEMPTS_OK):
    add(case(f"max_attempts.ok.{tag(i, text)}", f"--max-attempts {text} stops after exactly {n} attempts",
             ("--prefix", "ffffffff", "--dry-run", "--workers", "1", "--max-attempts", text, "--json"),
             Expectation(exit_code=4, files=NO_FILES, json={"status": "limited", "attempts": n})))
for i, text in enumerate(("0", "00", "0x0", "0b0", "0o0", "0_0")):
    add(case(f"max_attempts.zero.{tag(i, text)}", f"--max-attempts {text} is zero, which is no limit",
             ("--benchmark", "1ms", "--workers", "1", "--max-attempts", text), BENCH_TEXT))
for i, text in enumerate(("1_000", "4294967296", "9223372036854775807", "9223372036854775808", "18446744073709551615",
                          "0xffffffffffffffff", "01777777777777777777777", "0x_1")):
    add(case(f"max_attempts.parsed_then_rejected.{tag(i, text)}", f"--max-attempts {text} parses; benchmark rejects a limit",
             ("--benchmark", "1ms", "--max-attempts", text), validation_error("benchmark cannot be combined with search limits")))
ATTEMPTS_BAD = (("-1", "parse error"), ("-0", "parse error"), ("+1", "parse error"), ("+0", "parse error"), ("", "parse error"),
                ("_1", "parse error"), ("1_", "parse error"), ("1__0", "parse error"), ("0x", "parse error"), ("abc", "parse error"),
                ("1.5", "parse error"), ("0b2", "parse error"), ("09", "parse error"),
                ("18446744073709551616", "value out of range"), ("0x10000000000000000", "value out of range"),
                ("99999999999999999999999", "value out of range"))
for i, (text, why) in enumerate(ATTEMPTS_BAD):
    add(case(f"max_attempts.invalid.{tag(i, text)}", f"--max-attempts {text!r} is rejected by the parser",
             ("--benchmark", "1ms", "--max-attempts", text), parse_error(f'invalid value "{text}" for flag -max-attempts: {why}')))

# --- Durations: time.ParseDuration ---------------------------------------------------------------
# --timeout and --save-retry-timeout accept any valid value without waiting: the attempt cap or the
# validation error ends the run. --benchmark values near 30 ms also check the magnitude.


def elapsed_between(seconds):
    def check(ctx, obs):
        value = (obs.json or {}).get("elapsed_seconds")
        got = float(value.value) if value is not None and hasattr(value, "value") else None
        if got is None or not 0.9 * seconds <= got <= seconds + 5:
            return [f"elapsed_seconds {got} is not close to {seconds}"]
        return []
    return check


for i, text in enumerate(("30ms", "0.03s", ".03s", "00.03s", "30000us", "30000\u00b5s", "30000\u03bcs", "30000000ns", "0.0005m",
                          "0.00000833333h", "10ms20ms", "+30ms", "10ms10ms10ms", "0.030s")):
    add(case(f"duration.benchmark_magnitude.{tag(i, text)}", f"--benchmark {text} runs for about 30 ms",
             ("--benchmark", text, "--workers", "1", "--json"),
             Expectation(exit_code=0, files=NO_FILES, json={"status": "benchmark"}, check=elapsed_between(0.03)),
             attempts_nondeterministic=True))
for i, text in enumerate(("30ms", "0.03s", "30000\u00b5s", "30000\u03bcs")):
    add(case(f"duration.timeout_magnitude.{tag(i, text)}", f"--timeout {text} ends an unbounded search after about 30 ms",
             ("--timeout", text, "--prefix", "ffffffff", "--dry-run", "--workers", "1", "--json"),
             Expectation(exit_code=4, files=NO_FILES, json={"status": "limited", "error": "context deadline exceeded"},
                         check=elapsed_between(0.03)), attempts_nondeterministic=True))

DURATIONS_OK = ("1ns", "1us", "1\u00b5s", "1\u03bcs", "1ms", "1s", "1m", "1h", "1.5h", "1.5h30m", "+1s", "0.5s", ".5s", "1.s", "00.5s",
                "1h1m1s", "1h0m", "0s", "0", "-0", "+0", "0.0s", "-0s", "0h0m0s", "1ns1ns", "1.0000000001ns", "9223372036854775807ns",
                "2562047h47m16.854775807s", "2562047h", "1000000h")
for i, text in enumerate(DURATIONS_OK):
    add(case(f"duration.timeout_ok.{tag(i, text)}", f"--timeout {text!r} is a valid duration",
             ("--timeout", text, "--prefix", "ffffffff", *CAP),
             Expectation(exit_code=4, files=NO_FILES, stdout_regex=r"\ASearch failed: (search attempt limit reached|context deadline exceeded)\n\Z")))
DURATIONS_BAD = ("", "5", "0.5", "1d", "1w", "1y", "1 s", " 1s", "1s ", "s", ".", "+", "-", "1H", "1S", "1US", "1Ms", "1mm", "1sm", "1m1",
                 "1.2.3s", "1e3s", "1_0s", "0x10s", "1h-1m", "--1s", "+-1s", "1\u00b5", "1u", "\u0661s", "99999999999999999999s",
                 "9223372036854775808ns", "-9223372036854775809ns", "2562047h47m16.854775808s", "2562048h", "2562047h48m")
for i, text in enumerate(DURATIONS_BAD):
    for flag in ("timeout", "benchmark", "save-retry-timeout"):
        if flag != "timeout" and i % 3:  # the parser is shared: sample the other two flags
            continue
        add(case(f"duration.{flag.replace('-', '_')}_invalid.{tag(i, text)}", f"--{flag} {text!r} is not a duration",
                 (f"--{flag}", text, *BENCH), parse_error(f'invalid value "{text}" for flag -{flag}: parse error')))
for i, text in enumerate(("-1s", "-1ns", "-1h", "-0.5s", "-9223372036854775808ns")):
    add(case(f"duration.negative.{tag(i, text)}", f"--timeout {text} parses but is negative",
             ("--timeout", text, "--prefix", "ffffffff", *CAP), validation_error("timeout must not be negative")))
for i, text in enumerate(("0", "-0", "+0", "0s", "0.0h")):
    add(case(f"duration.save_retry_zero.{tag(i, text)}", f"--save-retry-timeout {text} is zero: no recovery option is set",
             ("--save-retry-timeout", text, *BENCH), BENCH_TEXT))
for i, text in enumerate(("1ns", "1s", "1h", "+1s")):
    add(case(f"duration.save_retry_positive.{tag(i, text)}", f"--save-retry-timeout {text} needs saving mode",
             ("--save-retry-timeout", text, *BENCH), validation_error("save recovery options require saving mode")))

# --- Repeated flags: the last value wins ------------------------------------------------------------

add(case("repeat.prefix_last_wins_valid", "the first, invalid prefix is replaced by the last one", ("--prefix", "zz", "--prefix", "ffffffff", *CAP), CAPPED))
add(case("repeat.prefix_last_wins_empty", "an empty last prefix removes the earlier one", ("--prefix", "ffffffff", "--prefix=", *CAP),
         validation_error("at least one of --prefix or --postfix must be specified")))
add(case("repeat.prefix_address", "--prefix a --prefix b finds an address starting with b", ("--prefix", "a", "--prefix", "b", "--dry-run", "--json"),
         Expectation(exit_code=0, files=NO_FILES, json={"status": "dry-run"}, check=starts_with("b")),
         random_identity=True, attempts_nondeterministic=True))
add(case("repeat.workers_3_then_1", "--workers 3 --workers 1 uses 1", ("--benchmark", "1ms", "--workers", "3", "--workers", "1"), bench_ok(workers=1)))
add(case("repeat.workers_1_then_2", "--workers 1 --workers 2 uses 2", ("--benchmark", "1ms", "--workers", "1", "--workers", "2"), bench_ok(workers=2)))
add(case("repeat.generator_independent_then_segmented", "the last generator wins", (*BENCH, "--generator", "independent", "--generator", "segmented"), BENCH_TEXT))
add(case("repeat.generator_segmented_then_independent", "the last generator wins", (*BENCH, "--generator", "segmented", "--generator", "independent"),
         bench_ok(generator="independent")))
add(case("repeat.json_true_then_false", "--json --json=false prints text", (*BENCH, "--json", "--json=false"), BENCH_TEXT))
add(case("repeat.json_false_then_true", "--json=false --json prints JSON", (*BENCH, "--json=false", "--json"), bench_json(), attempts_nondeterministic=True))
add(case("repeat.benchmark_then_zero", "--benchmark 0 after --benchmark 1ms turns benchmark mode off",
         ("--benchmark", "1ms", "--benchmark", "0", "--prefix", "ffffffff", *CAP), CAPPED))
add(case("repeat.max_attempts_last_wins", "--max-attempts 1 --max-attempts 3 stops at 3",
         ("--max-attempts", "1", "--max-attempts", "3", "--prefix", "ffffffff", "--dry-run", "--workers", "1", "--json"),
         Expectation(exit_code=4, files=NO_FILES, json={"status": "limited", "attempts": 3})))
add(case("repeat.timeout_negative_then_zero", "a later --timeout 0 replaces a negative one", ("--timeout=-1s", "--timeout", "0", "--prefix", "ffffffff", *CAP), CAPPED))
add(case("repeat.version_then_false", "--version --version=false does not print the version", ("--version", "--version=false", *BENCH), BENCH_TEXT))
add(case("repeat.inspect_then_empty", "--inspect X --inspect= is not inspection mode", ("--inspect", FIXTURE, "--inspect=", *BENCH), BENCH_TEXT, setup=setup_golden))

# --- A flag value may look like a flag -------------------------------------------------------------------

add(case("consume.prefix_takes_next_flag", "--prefix --dry-run: the value is the text --dry-run, not hex",
         ("--prefix", "--dry-run", "--workers", "1", "--max-attempts", "3"), validation_error("prefix must contain only hex characters [0-9a-fA-F]")))
add(case("consume.generator_takes_next_flag", "--generator --json: the value is the text --json", (*BENCH, "--generator", "--json"),
         validation_error("generator must be segmented or independent")))
add(case("consume.out_takes_next_flag", "--out --json: --json is the output name, so the result is text", (*BENCH, "--out", "--json"), BENCH_TEXT))
add(case("consume.workers_takes_next_flag", "--workers --json: the value is not an integer", ("--benchmark", "1ms", "--workers", "--json"),
         parse_error('invalid value "--json" for flag -workers: parse error')))
add(case("consume.benchmark_takes_next_flag", "--benchmark --workers 1: the value is not a duration", ("--benchmark", "--workers", "1"),
         parse_error('invalid value "--workers" for flag -benchmark: parse error')))
add(case("consume.max_attempts_takes_next_flag", "--max-attempts --json: the value is not an integer", ("--max-attempts", "--json", *BENCH),
         parse_error('invalid value "--json" for flag -max-attempts: parse error')))

# --- "--" and positional arguments ----------------------------------------------------------------------------

add(case("end.double_dash_after_flags", "-- after the flags is accepted", (*BENCH, "--"), BENCH_TEXT))
add(case("end.double_dash_alone", "-- alone leaves nothing to search for", ("--",), validation_error("at least one of --prefix or --postfix must be specified")))
add(case("end.double_dash_first", "-- before flags makes them positional", ("--", "--prefix", "a"),
         positional_error('["--prefix" "a"]')))
add(case("end.double_dash_then_positional", "an argument after -- is positional", (*BENCH, "--", "x"), positional_error('["x"]')))
add(case("end.double_dash_then_help", "--help after -- is positional", ("--", "--help"), positional_error('["--help"]')))
add(case("end.double_dash_as_value", "--prefix -- takes -- as its value", ("--prefix", "--", "--dry-run"),
         validation_error("prefix must contain only hex characters [0-9a-fA-F]")))
add(case("end.positional_stops_flag_parsing", "flags after a positional argument are positional too", (*BENCH, "x", "--json"), positional_error('["x" "--json"]')))
add(case("end.single_dash_is_positional", "a single - is positional", (*BENCH, "-"), positional_error('["-"]')))
add(case("end.single_dash_alone", "a lone - is positional", ("-",), positional_error('["-"]')))
add(case("end.empty_argument", "an empty argument is positional", (*BENCH, ""), positional_error('[""]')))
add(case("end.positional_before_help", "a positional before --help stops parsing, so there is no help", ("x", "--help"), positional_error('["x" "--help"]')))
add(case("end.version_then_positional", "--version extra is rejected", ("--version", "extra"), positional_error('["extra"]')))
add(case("end.inspect_then_positional", "--inspect X extra is rejected", ("--inspect", FIXTURE, "extra"), positional_error('["extra"]'), setup=setup_golden))
add(case("end.positional_before_validation", "a positional argument is reported before a pattern error", ("--prefix", "zz", "extra"), positional_error('["extra"]')))

# %q quoting of the positional list (strconv.Quote)
QUOTING = (
    ("space_and_accent", ("a b", "\u00e9"), '["a b" "\u00e9"]', None),
    ("emoji_and_cjk", ("\U0001F600", "\u65e5\u672c"), '["\U0001F600" "\u65e5\u672c"]', None),
    ("line_separator", ("\u2028",), '["\\u2028"]', None),
    ("zero_width_space", ("\u200b",), '["\\u200b"]', None),
    ("no_break_space", ("\u00a0",), '["\\u00a0"]', None),
    ("byte_order_mark", ("\ufeff",), '["\\ufeff"]', None),
    ("non_character", ("\U0010ffff",), '["\\U0010ffff"]', None),
    ("tab", ("tab\there",), '["tab\\there"]', NON_WINDOWS),
    ("controls", ("\x01\x7f",), '["\\x01\\x7f"]', NON_WINDOWS),
    ("newline_and_bell", ("a\nb\a",), '["a\\nb\\a"]', NON_WINDOWS),
    ("quote_and_backslash", ('a"b\\c',), '["a\\"b\\\\c"]', NON_WINDOWS),
    ("raw_non_utf8_byte", ("\udcff",), '["\\xff"]', frozenset({"linux"})),  # str that os.fsencode turns into byte 0xff
    ("raw_non_utf8_mixed", ("a\udcffb\udcc3",), '["a\\xffb\\xc3"]', frozenset({"linux"})),
    ("mixed_list", ("a b", "\u00e9", "x", "\u00e9"), '["a b" "\u00e9" "x" "\u00e9"]', None),
)
for name, items, shown, platforms in QUOTING:
    add(case(f"quoting.{name}", f"positional arguments are printed like Go %q: {shown}", (*BENCH, *items), positional_error(shown), platforms=platforms))

# --- Bad syntax, unknown flags, missing and empty values -----------------------------------------------------------

for i, (args, message) in enumerate((
        (("--nope",), "flag provided but not defined: -nope"), (("-nope",), "flag provided but not defined: -nope"),
        (("--nope=1",), "flag provided but not defined: -nope"), (("--Prefix", "a"), "flag provided but not defined: -Prefix"),
        (("--dry_run",), "flag provided but not defined: -dry_run"), (("-n",), "flag provided but not defined: -n"),
        (("--prefix-x", "a"), "flag provided but not defined: -prefix-x"), (("--prefix", "ffffffff", "--nope", "--dry-run"), "flag provided but not defined: -nope"),
        (("---x",), "bad flag syntax: ---x"), (("---prefix", "a"), "bad flag syntax: ---prefix"), (("---",), "bad flag syntax: ---"),
        (("--=1",), "bad flag syntax: --=1"), (("-=1",), "bad flag syntax: -=1"), (("--=x",), "bad flag syntax: --=x"),
        (("--version", "--nope"), "flag provided but not defined: -nope"), (("--nope", "--version"), "flag provided but not defined: -nope"))):
    add(case(f"syntax.{tag(i, ' '.join(args))}", f"{' '.join(args)!r} is a parse error", args, parse_error(message)))
for flag in ("prefix", "postfix", "workers", "out", "benchmark", "fallback-out", "save-retry-timeout", "max-attempts", "timeout", "generator", "inspect"):
    add(case(f"missing_value.{flag}", f"--{flag} at the end of the command line needs an argument", (f"--{flag}",), parse_error(f"flag needs an argument: -{flag}")))
add(case("missing_value.after_valid_flags", "a trailing --out has no value even after valid flags", (*BENCH, "--out"), parse_error("flag needs an argument: -out")))
add(case("empty_value.prefix", "--prefix= is empty, so no pattern is given", ("--prefix=", *CAP), validation_error("at least one of --prefix or --postfix must be specified")))
add(case("empty_value.postfix", "--postfix= is empty, so no pattern is given", ("--postfix=", *CAP), validation_error("at least one of --prefix or --postfix must be specified")))
add(case("empty_value.both", "--prefix= --postfix= give no pattern", ("--prefix=", "--postfix=", *CAP), validation_error("at least one of --prefix or --postfix must be specified")))
add(case("empty_value.prefix_with_postfix", "an empty prefix is fine when a postfix is given", ("--prefix=", "--postfix", "ffffffff", *CAP), capped(postfix="ffffffff")))
add(case("empty_value.prefix_separate", "--prefix '' is the same as --prefix=", ("--prefix", "", *CAP), validation_error("at least one of --prefix or --postfix must be specified")))
add(case("empty_value.out", "--out= is accepted where nothing is written", (*BENCH, "--out="), BENCH_TEXT))
add(case("empty_value.fallback_out", "--fallback-out= is not a recovery option", (*BENCH, "--fallback-out="), BENCH_TEXT))
add(case("empty_value.generator", "--generator= is accepted and printed with a trailing space", (*BENCH, "--generator="), bench_ok(generator="")))
add(case("empty_value.generator_json", "--generator= appears as an empty string in the JSON result", (*BENCH, "--json", "--generator="),
         bench_json(generator=""), attempts_nondeterministic=True))
add(case("empty_value.inspect", "--inspect= alone is not inspection mode", ("--inspect=",), validation_error("at least one of --prefix or --postfix must be specified")))
for flag, message in (("workers", "int"), ("max-attempts", "uint"), ("timeout", "duration"), ("benchmark", "duration"), ("save-retry-timeout", "duration")):
    add(case(f"empty_value.{flag}", f"--{flag}= is not a {message}", (f"--{flag}=", *BENCH), parse_error(f'invalid value "" for flag -{flag}: parse error')))
add(case("empty_value.equals_in_value", "--prefix=a=b keeps everything after the first =", ("--prefix=a=b", *CAP),
         validation_error("prefix must contain only hex characters [0-9a-fA-F]")))
add(case("empty_value.double_equals", "--prefix== has the value =", ("--prefix==", *CAP), validation_error("prefix must contain only hex characters [0-9a-fA-F]")))

# --- Help (REFERENCE_FACTS 3) -------------------------------------------------------------------------------------------

HELP = Expectation(exit_code=0, stdout=b"", stderr_regex=r"\A" + USAGE_RE + r"\Z", files=NO_FILES)
for i, args in enumerate((("-h",), ("-help",), ("--help",), ("--h",), ("--help=1",), ("--help=false",), ("-h=x",), ("--help", "extra"),
                          ("--help", "--nope"), ("--help", "--json"), ("--json", "--help"), ("--version", "--help"), ("--help", "--version"),
                          ("--help", "--prefix", "zz"), ("--help", "--workers", "0"), ("--prefix", "ffffffff", "--help"),
                          ("--benchmark", "1ms", "--help"))):
    add(case(f"help.{tag(i, ' '.join(args))}", f"{' '.join(args)!r} prints the usage text on stderr and exits 0", args, HELP))
add(case("help.after_unknown_flag", "an unknown flag before --help is a parse error", ("--nope", "--help"), parse_error("flag provided but not defined: -nope")))
add(case("help.after_flag_needing_value", "--workers --help takes --help as the value", ("--workers", "--help"),
         parse_error('invalid value "--help" for flag -workers: parse error')))
add(case("help.after_prefix", "--prefix --help takes --help as the prefix", ("--prefix", "--help", "--dry-run"),
         validation_error("prefix must contain only hex characters [0-9a-fA-F]")))
for workers, env in ((3, "3"), (1, "1"), (256, "1000")):
    exact = Expectation(exit_code=0, stdout=b"", stderr_lines=tuple(usage_lines(workers)), files=NO_FILES)
    anywhere = Expectation(exit_code=0, stdout=b"", stderr_regex=r"\A" + USAGE_RE + r"\Z", files=NO_FILES)
    add(case(f"help.gomaxprocs_{env}", f"with GOMAXPROCS={env} the printed workers default is {workers} (Go only)", ("--help",), exact,
             env={"GOMAXPROCS": env}, deviation=WORKERS_DEFAULT_DEVIATION, deviation_expect=anywhere))
msg = "flag provided but not defined: -nope"
add(case("help.gomaxprocs_3_parse_error", "with GOMAXPROCS=3 a parse error prints the same usage text, default 3 (Go only)", ("--nope",),
         Expectation(exit_code=2, stdout=b"", files=NO_FILES, stderr_lines=(msg, *usage_lines(3), f"Error: {msg}")),
         env={"GOMAXPROCS": "3"}, deviation=WORKERS_DEFAULT_DEVIATION, deviation_expect=parse_error(msg)))

# --- Version -------------------------------------------------------------------------------------------------------------

VERSION_JSON = Expectation(exit_code=0, stderr_lines=(), files=NO_FILES, json_keys=JSON_KEYS,
                           json={"status": "version", **EMPTY_ARRAYS, "attempts": 0, "generator": "segmented"})
for i, args in enumerate((("--version",), ("-version",), ("--version=true",), ("--version=1",), ("--version", "--json=false"),
                          ("--version", "--prefix", "zz"), ("--version", "--workers", "0", "--timeout=-1s", "--out", "x"),
                          ("--version", "--inspect", "does-not-exist"), ("--version", "--allow-inherited-windows-acl"),
                          ("--version", "--generator", "bogus"), ("--version", "--benchmark", "1ms", "--prefix", "a"))):
    add(case(f"version.text.{tag(i, ' '.join(args))}", f"{' '.join(args)!r} prints one version line and skips validation", args, VERSION_TEXT))
for i, args in enumerate((("--version", "--json"), ("--json", "--version"), ("--version", "--json", "--prefix", "ZZ"), ("--json", "--version", "--prefix=a"))):
    add(case(f"version.json.{tag(i, ' '.join(args))}", f"{' '.join(args)!r} prints a version result with empty arrays", args, VERSION_JSON))
add(case("version.json_generator_independent", "the version result carries the parsed generator", ("--version", "--json", "--generator", "independent"),
         Expectation(exit_code=0, files=NO_FILES, json={"status": "version", "generator": "independent"})))
add(case("version.json_generator_unvalidated", "the version result carries an unvalidated generator text", ("--version", "--json", "--generator", "bogus"),
         Expectation(exit_code=0, files=NO_FILES, json={"status": "version", "generator": "bogus"})))
add(case("version.json_generator_empty", "the version result carries an empty generator", ("--version", "--json", "--generator="),
         Expectation(exit_code=0, files=NO_FILES, json={"status": "version", "generator": ""})))
add(case("version.false_is_not_version", "--version=false alone falls through to pattern validation", ("--version=false",),
         validation_error("at least one of --prefix or --postfix must be specified")))
add(case("version.false_with_benchmark", "--version=0 with --benchmark runs the benchmark", ("--version=0", *BENCH), BENCH_TEXT))
add(case("version.help_wins", "--version --help prints help", ("--version", "--help"), HELP))
