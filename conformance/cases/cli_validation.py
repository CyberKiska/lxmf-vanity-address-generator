"""Validation cases: one per message of the validation order, plus precedence pairs.

Every run is either rejected before anything starts or observes through --benchmark or a capped
--dry-run, so nothing is written (files={} in every expectation). The order the tool checks is:
positional arguments, --version, --inspect, the Windows flag, generator, timeout, benchmark with
limits, save retry, recovery options, benchmark duration, benchmark or pattern rules, workers,
private exports with dry-run. Messages are exact; see cli_grammar for the shared helpers.
"""

from conformance.cases.cli_grammar import (
    BENCH, BENCH_TEXT, CAP, CAPPED, FIXTURE, INSPECTED, NON_WINDOWS, NO_FILES, WINDOWS, bench_ok, capped, setup_golden,
    tag, validation_error)
from conformance.harness import Case, Expectation

HEX_ONLY = "prefix must contain only hex characters [0-9a-fA-F]"
POSTFIX_HEX = "postfix must contain only hex characters [0-9a-fA-F]"
NEED_PATTERN = "at least one of --prefix or --postfix must be specified"
RECOVERY = "save recovery options require saving mode"
LIMITS = "benchmark cannot be combined with search limits"
INSPECT_PREFIX = r"\AError: --inspect cannot be combined with --\S+\n\Z"
D = ("--dry-run",)
CASES = []


def add(cid, description, args, expect, **kw):
    CASES.append(Case(id=f"cli_validation.{cid}", description=description, args=tuple(args), expect=expect, **kw))


def rejects(cid, args, message, description=None, **kw):
    add(cid, description or f"{' '.join(args)!r} is rejected: {message}", args, validation_error(message), **kw)


# --- 0. Pattern text is lowercased first, then measured in bytes ------------------------------------

add("lowercase.hex_digits", "prefix and postfix are lowercased before the search starts",
    ("--prefix", "ABCDEF01", "--postfix", "FFFFFFFF", *CAP), capped(prefix="abcdef01", postfix="ffffffff"))
add("lowercase.prefix_mixed_case", "a mixed-case prefix is shown in lower case", ("--prefix", "FfFfFfFf", *CAP), CAPPED)
# U+212A KELVIN SIGN is 3 bytes but lowercases to the 1-byte 'k': 11 of them are 33 bytes before and 11 after.
rejects("lowercase.length_measured_after_lowering", ("--prefix", "\u212a" * 11, *D), HEX_ONLY,
        "11 Kelvin signs (33 bytes) shrink to 11 bytes when lowercased, so only the hex rule fires")
rejects("lowercase.postfix_length_measured_after_lowering", ("--postfix", "\u212a" * 11, *D), POSTFIX_HEX)
# U+0130 (2 bytes) lowercases to a single byte in Go's simple mapping: 17 of them end up as 17 bytes.
rejects("lowercase.simple_case_mapping", ("--prefix", "\u0130" * 17, *D), HEX_ONLY,
        "U+0130 lowercases to one byte, so 17 of them pass the length rule and fail the hex rule")
rejects("lowercase.length_is_in_bytes_too_long", ("--prefix", "\u00e9" * 17, *D), "prefix must be 1-32 hex characters",
        "17 two-byte characters are 34 bytes: the length rule counts bytes")
rejects("lowercase.length_is_in_bytes_ok", ("--prefix", "\u00e9" * 16, *D), HEX_ONLY, "16 two-byte characters are 32 bytes: only the hex rule fires")
rejects("lowercase.postfix_length_is_in_bytes", ("--postfix", "\u00e9" * 17, *D), "postfix must be 1-32 hex characters")
# Invalid UTF-8 bytes become the 3-byte replacement character when the text is lowercased.
LINUX = frozenset({"linux"})
rejects("lowercase.invalid_bytes_grow", ("--prefix", "\udcff" * 11, *D), "prefix must be 1-32 hex characters",
        "11 invalid bytes become 11 three-byte replacement characters: 33 bytes", platforms=LINUX)
rejects("lowercase.invalid_bytes_short", ("--prefix", "\udcff" * 10 + "a", *D), HEX_ONLY, platforms=LINUX)

# --- 2. --inspect ------------------------------------------------------------------------------------

add("inspect.alone", "--inspect of the public fixture succeeds", ("--inspect", FIXTURE), INSPECTED, setup=setup_golden)
add("inspect.with_json", "--json is the one flag that may accompany --inspect", ("--inspect", FIXTURE, "--json"),
    Expectation(exit_code=0, files=NO_FILES, json={"status": "inspected", "address": "fae321c442e3c9bdcd7a3e79d850e03c"}), setup=setup_golden)
add("inspect.with_json_false", "--json=false with --inspect prints text", ("--inspect", FIXTURE, "--json=false"), INSPECTED, setup=setup_golden)
OTHERS = (("prefix", "a"), ("postfix", "a"), ("workers", "1"), ("out", "x"), ("dry-run", None), ("include-private-exports", None),
          ("benchmark", "1ms"), ("allow-inherited-windows-acl", None), ("allow-weak-output-protection", None), ("fallback-out", "x"),
          ("save-retry-timeout", "1s"), ("max-attempts", "1"), ("timeout", "1s"), ("generator", "segmented"))
for flag, value in OTHERS:
    given = (f"--{flag}",) if value is None else (f"--{flag}", value)
    rejects(f"inspect.with_{flag}", ("--inspect", FIXTURE, *given), f"--inspect cannot be combined with --{flag}", setup=setup_golden)
    rejects(f"inspect.with_{flag}_before", (*given, "--inspect", FIXTURE), f"--inspect cannot be combined with --{flag}", setup=setup_golden)
for flag in ("dry-run", "include-private-exports", "allow-inherited-windows-acl", "allow-weak-output-protection"):
    rejects(f"inspect.with_{flag}_false", ("--inspect", FIXTURE, f"--{flag}=false"), f"--inspect cannot be combined with --{flag}",
            f"an explicit --{flag}=false still counts as a combined flag", setup=setup_golden)
for i, extra in enumerate((("--prefix", "a", "--workers", "1"), ("--dry-run", "--timeout", "1s", "--generator", "independent"),
                           ("--json", "--out", "x", "--max-attempts", "1"), tuple(f"--{f}" for f in ("dry-run", "include-private-exports")))):
    # Go reports one of several extra flags in random order: assert only the message shape, and compare only exit and files.
    add(f"inspect.several_flags.{tag(i, ' '.join(extra))}", f"--inspect with {' '.join(extra)!r} names one of the extra flags",
        ("--inspect", FIXTURE, *extra), Expectation(exit_code=2, stdout=b"", stderr_regex=INSPECT_PREFIX, files=NO_FILES),
        setup=setup_golden, compare=frozenset({"exit", "files"}))
add("inspect.empty_value_is_not_inspection", "--inspect= with a bad prefix is validated as a normal search", ("--inspect=", "--prefix", "zz", *D),
    validation_error(HEX_ONLY))
add("inspect.empty_value_needs_pattern", "--inspect= with --dry-run and no pattern asks for one", ("--inspect=", *D), validation_error(NEED_PATTERN))
add("inspect.version_wins", "--version beats the --inspect combination rule", ("--inspect", FIXTURE, "--prefix", "a", "--version"),
    Expectation(exit_code=0, files=NO_FILES, stdout_regex=r"\Alxmf-vanity "), setup=setup_golden)

# --- 3. --allow-inherited-windows-acl -------------------------------------------------------------------

rejects("windows_flag.posix", (*BENCH, "--allow-inherited-windows-acl"), "--allow-inherited-windows-acl is only valid on Windows",
        platforms=NON_WINDOWS)
rejects("windows_flag.posix_with_dry_run", (*D, "--prefix", "a", "--allow-inherited-windows-acl"),
        "--allow-inherited-windows-acl is only valid on Windows", platforms=NON_WINDOWS)
rejects("windows_flag.beats_generator_on_posix", (*BENCH, "--allow-inherited-windows-acl", "--generator", "bogus"),
        "--allow-inherited-windows-acl is only valid on Windows", platforms=NON_WINDOWS)
rejects("windows_flag.beats_workers_on_posix", ("--benchmark", "1ms", "--workers", "0", "--allow-inherited-windows-acl"),
        "--allow-inherited-windows-acl is only valid on Windows", platforms=NON_WINDOWS)
add("windows_flag.windows_accepts", "on Windows the flag is accepted", (*BENCH, "--allow-inherited-windows-acl"), BENCH_TEXT, platforms=WINDOWS)
rejects("windows_flag.generator_next_on_windows", (*BENCH, "--allow-inherited-windows-acl", "--generator", "bogus"),
        "generator must be segmented or independent", platforms=WINDOWS)
add("windows_flag.false_is_accepted", "--allow-inherited-windows-acl=false is accepted everywhere", (*BENCH, "--allow-inherited-windows-acl=false"), BENCH_TEXT)

# --- 4. generator ---------------------------------------------------------------------------------------

for i, text in enumerate(("bogus", "Segmented", "INDEPENDENT", " segmented", "segmented ", "seg", "independent2", "segmented,independent", "0")):
    rejects(f"generator.invalid.{tag(i, text)}", (*BENCH, "--generator", text), "generator must be segmented or independent")
rejects("generator.invalid_with_pattern", ("--prefix", "ffffffff", *CAP, "--generator", "x"), "generator must be segmented or independent")
add("generator.segmented", "--generator segmented is accepted", (*BENCH, "--generator", "segmented"), BENCH_TEXT)
add("generator.independent", "--generator independent is accepted", (*BENCH, "--generator", "independent"), bench_ok(generator="independent"))
add("generator.independent_search", "--generator independent works with a capped search", ("--prefix", "ffffffff", *CAP, "--generator", "independent"),
    capped(prefix="ffffffff", generator="independent"))
add("generator.empty_is_accepted", "the empty generator is accepted and printed as 'Generator: ' with a trailing space",
    (*BENCH, "--generator="), bench_ok(generator=""))
add("generator.empty_search", "the empty generator behaves as segmented in a search", ("--prefix", "ffffffff", *CAP, "--generator="),
    capped(prefix="ffffffff", generator=""))

# --- 5. timeout ---------------------------------------------------------------------------------------------

for i, text in enumerate(("-1s", "-1ns", "-1h", "-0.5s", "-1m30s")):
    rejects(f"timeout.negative.{tag(i, text)}", (f"--timeout={text}", "--prefix", "ffffffff", *CAP), "timeout must not be negative")
rejects("timeout.negative_with_benchmark", (*BENCH, "--timeout=-1s"), "timeout must not be negative")
add("timeout.zero_is_unlimited", "--timeout 0 is accepted", ("--timeout", "0", "--prefix", "ffffffff", *CAP), CAPPED)

# --- 6. benchmark with search limits ---------------------------------------------------------------------------

rejects("benchmark_limits.timeout", (*BENCH, "--timeout", "1s"), LIMITS)
rejects("benchmark_limits.max_attempts", (*BENCH, "--max-attempts", "1"), LIMITS)
rejects("benchmark_limits.both", (*BENCH, "--timeout", "1s", "--max-attempts", "1"), LIMITS)
rejects("benchmark_limits.tiny_timeout", (*BENCH, "--timeout", "1ns"), LIMITS)
add("benchmark_limits.zero_limits_are_fine", "zero limits do not count as limits", (*BENCH, "--timeout", "0", "--max-attempts", "0"), BENCH_TEXT)

# --- 7. save retry timeout -----------------------------------------------------------------------------------------

for i, text in enumerate(("-1s", "-1ns", "-1h")):
    rejects(f"save_retry.negative.{tag(i, text)}", (f"--save-retry-timeout={text}", *D, "--prefix", "ffffffff"), "save retry timeout must not be negative")
rejects("save_retry.negative_with_benchmark", (*BENCH, "--save-retry-timeout=-1s"), "save retry timeout must not be negative")

# --- 8. recovery options need saving mode ----------------------------------------------------------------------------

rejects("recovery.dry_run_fallback", (*D, "--prefix", "ffffffff", "--fallback-out", "x"), RECOVERY)
rejects("recovery.dry_run_save_retry", (*D, "--prefix", "ffffffff", "--save-retry-timeout", "1s"), RECOVERY)
rejects("recovery.benchmark_fallback", (*BENCH, "--fallback-out", "x"), RECOVERY)
rejects("recovery.benchmark_save_retry", (*BENCH, "--save-retry-timeout", "1s"), RECOVERY)
rejects("recovery.both_options", (*D, "--prefix", "ffffffff", "--fallback-out", "x", "--save-retry-timeout", "1s"), RECOVERY)
add("recovery.dry_run_zero_save_retry", "--save-retry-timeout 0 is not a recovery option", ("--save-retry-timeout", "0", "--prefix", "ffffffff", *CAP), CAPPED)
add("recovery.dry_run_empty_fallback", "--fallback-out= is not a recovery option", ("--fallback-out=", "--prefix", "ffffffff", *CAP), CAPPED)

# --- 9. benchmark duration -----------------------------------------------------------------------------------------------

for i, text in enumerate(("-1s", "-1ns", "-1h", "-0.5s")):
    rejects(f"benchmark_duration.negative.{tag(i, text)}", (f"--benchmark={text}",), "benchmark duration must not be negative")
rejects("benchmark_duration.negative_with_pattern", ("--benchmark=-1s", "--prefix", "a", *D), "benchmark duration must not be negative")
add("benchmark_duration.zero_runs_a_search", "--benchmark 0 turns benchmark mode off", ("--benchmark", "0", "--prefix", "ffffffff", *CAP), CAPPED)
add("benchmark_duration.negative_zero_runs_a_search", "--benchmark=-0s is zero", ("--benchmark=-0s", "--prefix", "ffffffff", *CAP), CAPPED)
rejects("benchmark_duration.zero_needs_pattern", ("--benchmark", "0", *D), NEED_PATTERN, "--benchmark 0 with no pattern asks for one")

# --- 10. benchmark mode and pattern rules ------------------------------------------------------------------------------------

rejects("benchmark_mode.prefix", (*BENCH, "--prefix", "a"), "--benchmark cannot be combined with --prefix or --postfix")
rejects("benchmark_mode.postfix", (*BENCH, "--postfix", "a"), "--benchmark cannot be combined with --prefix or --postfix")
rejects("benchmark_mode.both_patterns", (*BENCH, "--prefix", "a", "--postfix", "b"), "--benchmark cannot be combined with --prefix or --postfix")
rejects("benchmark_mode.invalid_prefix_is_still_a_prefix", (*BENCH, "--prefix", "zz"), "--benchmark cannot be combined with --prefix or --postfix")
rejects("benchmark_mode.dry_run", (*BENCH, "--dry-run"), "--benchmark cannot be combined with --dry-run")
rejects("benchmark_mode.dry_run_value_true", (*BENCH, "--dry-run=true"), "--benchmark cannot be combined with --dry-run")
rejects("benchmark_mode.private_exports", (*BENCH, "--include-private-exports"), "--benchmark cannot be combined with --include-private-exports")
rejects("benchmark_mode.dry_run_beats_exports", (*BENCH, "--dry-run", "--include-private-exports"), "--benchmark cannot be combined with --dry-run")
rejects("benchmark_mode.prefix_beats_dry_run", (*BENCH, "--dry-run", "--prefix", "a"), "--benchmark cannot be combined with --prefix or --postfix")
rejects("benchmark_mode.prefix_beats_all", (*BENCH, "--prefix", "a", "--dry-run", "--include-private-exports"),
        "--benchmark cannot be combined with --prefix or --postfix")
rejects("pattern.none", D, NEED_PATTERN)
rejects("pattern.none_with_json", (*D, "--json"), NEED_PATTERN, "--json does not turn a validation error into JSON: stdout stays empty")
rejects("pattern.none_with_workers", (*D, "--workers", "4"), NEED_PATTERN)
rejects("pattern.prefix_33", ("--prefix", "a" * 33, *D), "prefix must be 1-32 hex characters")
rejects("pattern.postfix_33", ("--postfix", "b" * 33, *D), "postfix must be 1-32 hex characters")
rejects("pattern.prefix_33_uppercase", ("--prefix", "A" * 33, *D), "prefix must be 1-32 hex characters")
rejects("pattern.prefix_100", ("--prefix", "a" * 100, *D), "prefix must be 1-32 hex characters")
for i, text in enumerate(("g", "zz", "0x1", "ab cd", "a-b", "\uff41", "a\u00e9", "1234567890123456789012345678901x")):
    rejects(f"pattern.prefix_not_hex.{tag(i, text)}", ("--prefix", text, *D), HEX_ONLY)
for i, text in enumerate(("g", "zz", "0x1", "ab cd", "a-b", "\uff41", "a\u00e9")):
    rejects(f"pattern.postfix_not_hex.{tag(i, text)}", ("--postfix", text, *D), POSTFIX_HEX)
rejects("pattern.combined_33", ("--prefix", "a" * 16, "--postfix", "b" * 17, *D), "combined prefix and postfix length must not exceed 32 hex characters")
rejects("pattern.combined_33_unbalanced", ("--prefix", "a" * 32, "--postfix", "b", *D), "combined prefix and postfix length must not exceed 32 hex characters")
rejects("pattern.combined_64", ("--prefix", "a" * 32, "--postfix", "b" * 32, *D), "combined prefix and postfix length must not exceed 32 hex characters")
add("pattern.combined_32_accepted", "16 + 16 hex characters are accepted", ("--prefix", "a" * 16, "--postfix", "b" * 16, *CAP),
    capped(prefix="a" * 16, postfix="b" * 16))
add("pattern.combined_32_one_and_31", "1 + 31 hex characters are accepted", ("--prefix", "a", "--postfix", "b" * 31, *CAP), capped(prefix="a", postfix="b" * 31))
add("pattern.prefix_32_accepted", "a 32-character prefix is accepted", ("--prefix", "a" * 32, *CAP), capped(prefix="a" * 32))
add("pattern.postfix_32_accepted", "a 32-character postfix is accepted", ("--postfix", "b" * 32, *CAP), capped(postfix="b" * 32))
add("pattern.uppercase_accepted", "uppercase hex is accepted and lowercased", ("--prefix", "F" * 8, *CAP), CAPPED)
add("pattern.single_character_accepted", "a single hex character is accepted", ("--prefix", "f", "--dry-run", "--workers", "1", "--json"),
    Expectation(exit_code=0, files=NO_FILES, json={"status": "dry-run"}), random_identity=True, attempts_nondeterministic=True)
# order inside the pattern group
rejects("pattern.order_prefix_length_before_postfix_length", ("--prefix", "a" * 33, "--postfix", "b" * 33, *D), "prefix must be 1-32 hex characters")
rejects("pattern.order_postfix_length_before_prefix_hex", ("--prefix", "zz", "--postfix", "b" * 33, *D), "postfix must be 1-32 hex characters")
rejects("pattern.order_prefix_length_before_postfix_hex", ("--prefix", "a" * 33, "--postfix", "zz", *D), "prefix must be 1-32 hex characters")
rejects("pattern.order_prefix_hex_before_postfix_hex", ("--prefix", "zz", "--postfix", "yy", *D), HEX_ONLY)
rejects("pattern.order_postfix_hex_before_combined", ("--prefix", "a" * 20, "--postfix", "b" * 12 + "z", *D), POSTFIX_HEX)
rejects("pattern.order_prefix_hex_before_combined", ("--prefix", "a" * 19 + "z", "--postfix", "b" * 20, *D), HEX_ONLY)

# --- 11. workers --------------------------------------------------------------------------------------------------------------

rejects("workers.zero_benchmark", ("--benchmark", "1ms", "--workers", "0"), "workers must be at least 1")
rejects("workers.negative_benchmark", ("--benchmark", "1ms", "--workers", "-1"), "workers must be at least 1")
rejects("workers.zero_search", ("--prefix", "ffffffff", *D, "--workers", "0"), "workers must be at least 1")
rejects("workers.257_benchmark", ("--benchmark", "1ms", "--workers", "257"), "workers must not exceed 256")
rejects("workers.257_search", ("--prefix", "ffffffff", *D, "--workers", "257"), "workers must not exceed 256")
rejects("workers.1000_underscore", ("--benchmark", "1ms", "--workers=1_000"), "workers must not exceed 256")
add("workers.256_accepted", "256 workers are accepted", ("--benchmark", "1ms", "--workers", "256"), bench_ok(workers=256))
add("workers.1_accepted", "1 worker is accepted", ("--benchmark", "1ms", "--workers", "1"), bench_ok(workers=1))

# --- 12. private exports with dry-run ----------------------------------------------------------------------------------------------

rejects("exports.with_dry_run", ("--prefix", "ffffffff", *D, "--include-private-exports"), "--include-private-exports cannot be used with --dry-run")
rejects("exports.with_dry_run_other_order", ("--include-private-exports", "--dry-run", "--prefix", "ffffffff"), "--include-private-exports cannot be used with --dry-run")
add("exports.false_with_dry_run", "--include-private-exports=false with --dry-run is fine", ("--prefix", "ffffffff", *CAP, "--include-private-exports=false"), CAPPED)

# --- Precedence: two broken rules at once; the earlier rule is reported --------------------------------------------------------------------

PAIRS = (  # (name, args, message that wins, platforms)
    ("generator_beats_timeout", (*D, "--prefix", "a", "--generator", "bogus", "--timeout=-1s"), "generator must be segmented or independent", None),
    ("generator_beats_benchmark_limits", ("--generator", "bogus", *BENCH, "--timeout", "1s"), "generator must be segmented or independent", None),
    ("timeout_beats_benchmark_duration", ("--benchmark=-1s", "--timeout=-1s"), "timeout must not be negative", None),
    ("timeout_beats_save_retry", (*D, "--prefix", "a", "--timeout=-1s", "--save-retry-timeout=-1s"), "timeout must not be negative", None),
    ("timeout_negative_beats_benchmark_limit", (*BENCH, "--timeout=-1s", "--max-attempts", "1"), "timeout must not be negative", None),
    ("benchmark_limits_beat_save_retry", (*BENCH, "--timeout", "1s", "--save-retry-timeout=-1s"), LIMITS, None),
    ("benchmark_limits_beat_recovery", (*BENCH, "--timeout", "1s", "--fallback-out", "x"), LIMITS, None),
    ("benchmark_limits_beat_benchmark_mode", (*BENCH, "--max-attempts", "1", "--prefix", "a"), LIMITS, None),
    ("save_retry_beats_recovery", (*D, "--prefix", "a", "--save-retry-timeout=-1s", "--fallback-out", "x"), "save retry timeout must not be negative", None),
    ("recovery_beats_benchmark_duration", (*D, "--fallback-out", "x", "--benchmark=-1s", "--prefix", "a"), RECOVERY, None),
    ("recovery_beats_benchmark_mode", (*BENCH, "--fallback-out", "x", "--prefix", "a"), RECOVERY, None),
    ("recovery_beats_pattern", (*D, "--fallback-out", "x"), RECOVERY, None),
    ("benchmark_duration_beats_pattern", ("--benchmark=-1s",), "benchmark duration must not be negative", None),
    ("benchmark_duration_beats_workers", ("--benchmark=-1s", "--workers", "0"), "benchmark duration must not be negative", None),
    ("benchmark_mode_beats_workers", (*BENCH[:2], "--prefix", "a", "--workers", "0"), "--benchmark cannot be combined with --prefix or --postfix", None),
    ("pattern_beats_workers", (*D, "--workers", "0"), NEED_PATTERN, None),
    ("pattern_length_beats_workers", ("--prefix", "a" * 33, *D, "--workers", "0"), "prefix must be 1-32 hex characters", None),
    ("workers_beat_exports", ("--prefix", "a", *D, "--include-private-exports", "--workers", "0"), "workers must be at least 1", None),
    ("workers_exceed_beats_exports", ("--prefix", "a", *D, "--include-private-exports", "--workers", "300"), "workers must not exceed 256", None),
    ("pattern_beats_exports", (*D, "--include-private-exports"), NEED_PATTERN, None),
    ("windows_flag_beats_generator", (*BENCH, "--allow-inherited-windows-acl", "--generator", "x"), "--allow-inherited-windows-acl is only valid on Windows", NON_WINDOWS),
    ("windows_flag_beats_timeout", (*D, "--prefix", "a", "--allow-inherited-windows-acl", "--timeout=-1s"), "--allow-inherited-windows-acl is only valid on Windows", NON_WINDOWS),
    ("windows_flag_beats_pattern", (*D, "--allow-inherited-windows-acl"), "--allow-inherited-windows-acl is only valid on Windows", NON_WINDOWS),
    ("windows_flag_does_not_beat_inspect", ("--inspect", FIXTURE, "--allow-inherited-windows-acl"), "--inspect cannot be combined with --allow-inherited-windows-acl", None),
)
for name, args, message, platforms in PAIRS:
    rejects(f"precedence.{name}", args, message, platforms=platforms, setup=setup_golden if FIXTURE in args else None)

# --- Parse errors and positional arguments come before validation ---------------------------------------------------------------------------

rejects("order.positional_before_validation", ("--prefix", "zz", *D, "extra"),
        'unexpected positional arguments ["extra"]; all options must use flags')
rejects("order.positional_before_inspect_rule", ("--inspect", FIXTURE, "--prefix", "a", "extra"),
        'unexpected positional arguments ["extra"]; all options must use flags', setup=setup_golden)
add("order.parse_error_before_validation", "a flag parse error is reported before any validation rule", ("--workers", "0", "--nope"),
    Expectation(exit_code=2, stdout=b"", files=NO_FILES, stderr_regex=r"\Aflag provided but not defined: -nope\nUsage of lxmf-vanity:\n"))
add("order.parse_error_before_negative_timeout", "an invalid boolean is reported before a negative timeout", ("--timeout=-1s", "--json=maybe"),
    Expectation(exit_code=2, stdout=b"", files=NO_FILES, stderr_regex=r'\Ainvalid boolean value "maybe" for -json: parse error\nUsage of lxmf-vanity:\n'))
rejects("json.validation_error_has_empty_stdout", ("--json", *D, "--workers", "0", "--prefix", "a"), "workers must be at least 1")
rejects("json.recovery_error_has_empty_stdout", ("--json", *BENCH, "--fallback-out", "x"), RECOVERY)
rejects("json.positional_error_has_empty_stdout", ("--json", *BENCH, "extra"), 'unexpected positional arguments ["extra"]; all options must use flags')
