"""Search-mode cases: dry-run, benchmark, attempt caps and timeouts. Nothing is ever written (files={}).

Dry-run finds a short pattern and prints the match; the check recomputes the address from public_key
(REFERENCE_FACTS 2) and compares it with the pattern. Benchmark runs for a fixed time. Caps and timeouts
use a 12-character prefix that cannot match by chance (16**-12 per attempt), so the result is always
"limited". The stderr lines and their order are those of REFERENCE_FACTS 9. The helpers marked private
are local to the case modules and may move to fixtures.py later.
"""

import hashlib

from conformance.harness import Case, Expectation

NO_FILES = {}
GENERATORS = ("segmented", "independent")
IMPOSSIBLE = "ffffffffffff"  # 12 hex characters: the match chance per attempt is 2**-48
EMPTY_ARRAYS = {"verified_files": [], "unverified_files": [], "deviations": [], "notices": []}
KEYS_FOUND = ("status", "address", "identity_hash", "x25519_public", "ed25519_public", "public_key", "verified_files",
              "unverified_files", "deviations", "notices", "attempts", "elapsed_seconds", "generator", "version")
KEYS_NO_IDENTITY = tuple(k for k in KEYS_FOUND if k not in KEYS_FOUND[1:6])
KEYS_FAILED = KEYS_NO_IDENTITY + ("error",)
EXPECTED_SUFFIX = " (geometric expectation; not a deadline)"
WARNING_DRY_RUN = "Warning: --dry-run discards the matching private identity."
HINT = "For expensive searches, configure --fallback-out in another protected directory."
CASES = []


# --- private helpers (candidates for fixtures.py) -------------------------------------------------------

def lxmf_address(public_key_hex):
    """REFERENCE_FACTS 2: address from the 64-byte public identity."""
    identity_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()[:16]
    name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]
    return hashlib.sha256(name_hash + identity_hash).digest()[:16].hex()


def public_problems(fields):
    """Failures for the identity fields of a JSON result (lengths are checked by the harness)."""
    fails = []
    if fields["x25519_public"] + fields["ed25519_public"] != fields["public_key"]:
        fails.append("public_key is not x25519_public + ed25519_public")
    if lxmf_address(fields["public_key"]) != fields["address"]:
        fails.append("address is not derived from public_key")
    identity_hash = hashlib.sha256(bytes.fromhex(fields["public_key"])).digest()[:16].hex()
    if identity_hash != fields["identity_hash"]:
        fails.append("identity_hash is not SHA-256(public_key)[:16]")
    return fails


def search_lines(prefix, postfix, workers, generator="segmented", *, dry_run=False, hint=False, benchmark=False):
    """Stderr of a search run, in order (REFERENCE_FACTS 9), up to and including 'search started'."""
    lines = [f'LXMF vanity search: prefix="{prefix.lower()}" postfix="{postfix.lower()}" workers={workers}']
    if not benchmark:
        lines.append(f"Expected attempts: {16 ** (len(prefix) + len(postfix))}{EXPECTED_SUFFIX}")
    if hint:
        lines.append(HINT)
    if dry_run:
        lines.append(WARNING_DRY_RUN)
    return tuple(lines + [f"Generator: {generator}", "search started"])


def found_check(prefix, postfix):
    def check(ctx, obs):
        fields = obs.json
        fails = public_problems(fields)
        address = fields["address"]
        if not (address.startswith(prefix.lower()) and address.endswith(postfix.lower())):
            fails.append("address does not match the lowercased pattern")
        if fields["attempts"].value < 1:
            fails.append("attempts is not positive")
        return fails
    return check


def add(cid, description, args, expect, **kw):
    CASES.append(Case(id=f"search_modes.{cid}", description=description, args=tuple(args), expect=expect, **kw))


# --- 1. Dry-run -------------------------------------------------------------------------------------------

DRY_PATTERNS = (  # (prefix, postfix): one and two characters, odd and even totals, upper and lower case
    ("0", ""), ("A", ""), ("ab", ""), ("AB", ""), ("", "7"), ("", "F"), ("", "0a"), ("", "CD"),
    ("a", "b"), ("AB", "c"), ("a", "bC"), ("A", "B"),
)
for i, (pre, post) in enumerate(DRY_PATTERNS):
    for generator in GENERATORS if i in (0, 3, 9) else GENERATORS[:1]:
        args = ["--dry-run", "--workers", "2", "--json", "--generator", generator]
        args += (["--prefix", pre] if pre else []) + (["--postfix", post] if post else [])
        case = f"dry_run.pre{len(pre)}_post{len(post)}_{'upper' if (pre + post).isupper() or (pre + post).lower() != pre + post else 'lower'}_{generator}_{i}"
        add(case, f"dry-run for prefix {pre!r} postfix {post!r} ({generator}): exit 0, status dry-run, matching address, no files",
            args, Expectation(
                exit_code=0, files=NO_FILES, json_keys=KEYS_FOUND,
                json={"status": "dry-run", **EMPTY_ARRAYS, "generator": generator},
                stderr_lines=search_lines(pre, post, 2, generator, dry_run=True), check=found_check(pre, post)),
            random_identity=True, attempts_nondeterministic=True)

add("dry_run.text", "dry-run text mode prints the found address and the attempt count",
    ("--dry-run", "--workers", "1", "--prefix", "A", "--postfix", "b"),
    Expectation(exit_code=0, files=NO_FILES, stdout_regex=r"\AFound matching address: a[0-9a-f]{30}b\n  Total attempts: [1-9][0-9]*\n\Z",
                stderr_lines=search_lines("A", "b", 1, dry_run=True)),
    compare=frozenset({"exit", "files", "stderr_markers"}))

# --- 2. Benchmark -----------------------------------------------------------------------------------------


def bench_check(ctx, obs):
    fields, fails = obs.json, []
    if fields["attempts"].value < 1:
        fails.append("attempts is not positive")
    if fields["elapsed_seconds"].value < 0.05:
        fails.append("elapsed_seconds is below the requested 50 ms")
    return fails


# A Go duration (for example 51.13ms, 1.2s, 950.5us) and formatNumber output (1234, 6.04K, 1.20M, 1.23e+12).
BENCH_TEXT = (r"\ABenchmark complete: (\d+|\d+\.\d\d[KMG]|\d\.\d\de\+\d\d) attempts in [0-9.]+(ns|µs|ms|s) "
              r"\((\d+|\d+\.\d\d[KMG]|\d\.\d\de\+\d\d)/s average\), generator=%s\n\Z")
for workers in (1, 2):
    for generator in GENERATORS:
        gen = ("--generator", generator)
        add(f"benchmark.json_w{workers}_{generator}", f"--benchmark 50ms with {workers} worker(s), {generator}: status benchmark, no Expected attempts line",
            ("--benchmark", "50ms", "--workers", str(workers), "--json", *gen),
            Expectation(exit_code=0, files=NO_FILES, json_keys=KEYS_NO_IDENTITY,
                        json={"status": "benchmark", **EMPTY_ARRAYS, "generator": generator},
                        stderr_lines=search_lines("", "", workers, generator, benchmark=True), check=bench_check),
            attempts_nondeterministic=True)
        add(f"benchmark.text_w{workers}_{generator}", f"--benchmark 50ms text mode with {workers} worker(s), {generator}: one summary line",
            ("--benchmark", "50ms", "--workers", str(workers), *gen),
            Expectation(exit_code=0, files=NO_FILES, stdout_regex=BENCH_TEXT % generator,
                        stderr_lines=search_lines("", "", workers, generator, benchmark=True)),
            compare=frozenset({"exit", "files", "stderr_markers"}))

# --- 3. Attempt caps and timeouts ---------------------------------------------------------------------------

LIMITS = (1, 3, 7, 64, 65, 1031)
for generator in GENERATORS:
    for n in LIMITS:
        for workers in (1, 2, 7):
            add(f"limit.n{n}_w{workers}_{generator}", f"--max-attempts {n} with {workers} worker(s), {generator}: exit 4, limited, exactly {n} attempts",
                ("--prefix", IMPOSSIBLE, "--dry-run", "--max-attempts", str(n), "--workers", str(workers), "--generator", generator, "--json"),
                Expectation(exit_code=4, files=NO_FILES, json_keys=KEYS_FAILED,
                            json={"status": "limited", **EMPTY_ARRAYS, "attempts": n, "generator": generator, "error": "search attempt limit reached"},
                            stderr_lines=search_lines(IMPOSSIBLE, "", workers, generator, dry_run=True)))
    add(f"timeout.json_{generator}", f"--timeout 100ms ({generator}): exit 4, limited, context deadline exceeded",
        ("--prefix", IMPOSSIBLE, "--dry-run", "--timeout", "100ms", "--workers", "2", "--generator", generator, "--json"),
        Expectation(exit_code=4, files=NO_FILES, json_keys=KEYS_FAILED,
                    json={"status": "limited", **EMPTY_ARRAYS, "generator": generator, "error": "context deadline exceeded"},
                    stderr_lines=search_lines(IMPOSSIBLE, "", 2, generator, dry_run=True),
                    check=lambda ctx, obs: [] if obs.json["attempts"].value > 0 else ["attempts is not positive"]),
        attempts_nondeterministic=True)
add("limit.text", "--max-attempts text mode prints 'Search failed' and exits 4",
    ("--prefix", IMPOSSIBLE, "--dry-run", "--max-attempts", "5", "--workers", "2"),
    Expectation(exit_code=4, files=NO_FILES, stdout="Search failed: search attempt limit reached\n",
                stderr_lines=search_lines(IMPOSSIBLE, "", 2, dry_run=True)),
    compare=frozenset({"exit", "stdout", "files", "stderr_markers"}))
add("timeout.text", "--timeout text mode prints 'Search failed: context deadline exceeded' and exits 4",
    ("--prefix", IMPOSSIBLE, "--dry-run", "--timeout", "100ms", "--workers", "2"),
    Expectation(exit_code=4, files=NO_FILES, stdout="Search failed: context deadline exceeded\n",
                stderr_lines=search_lines(IMPOSSIBLE, "", 2, dry_run=True)),
    compare=frozenset({"exit", "stdout", "files", "stderr_markers"}))
add("limit.postfix_and_prefix", "a cap also ends a combined prefix and postfix search (12 characters in all)",
    ("--prefix", "ffff", "--postfix", "eeeeeeee", "--dry-run", "--max-attempts", "9", "--workers", "3", "--json"),
    Expectation(exit_code=4, files=NO_FILES, json={"status": "limited", "attempts": 9, "error": "search attempt limit reached"},
                stderr_lines=search_lines("ffff", "eeeeeeee", 3, dry_run=True)))
