"""Black-box conformance harness for the lxmf-vanity command-line tool.

A Case runs the tool as a subprocess in a fresh temporary directory with a
scrubbed environment, records an Observation (exit code, streams, created
files), normalizes it, and checks it against an Expectation. In differential
mode the same case also runs against a reference binary and the normalized
observations are compared.

Standard library only. Secrets are never printed: every message is scrubbed
against the secrets the run knows about.
"""

import base64
import dataclasses
import fnmatch
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from decimal import Decimal

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TIMEOUT = 30.0
PLATFORMS = frozenset({"linux", "darwin", "windows"})
COMPARE_FIELDS = frozenset({"exit", "stdout", "stdout_exact", "json", "files", "stderr", "stderr_markers", "sidecars"})
DEFAULT_COMPARE = frozenset({"exit", "json", "files", "stderr_markers"})
PUBLIC_FIELDS = ("address", "identity_hash", "x25519_public", "ed25519_public", "public_key")
HEX_LENGTHS = {"address": 32, "identity_hash": 32, "x25519_public": 64, "ed25519_public": 64, "public_key": 128}
MIN_SECRET_BYTES = 8  # shorter values would make encoded needles match by chance
MAX_TEXT = 1 << 20  # largest sidecar read into memory
MAX_REPORT_TEXT = 16384
MARKER_LINE = re.compile(r"(Notice: |Warning: |Error: |Generator: |search started$|LXMF vanity search: |"
                         r"Expected attempts: |For expensive searches|Save recovery: |Discard armed)")
CRASH_LINE = re.compile(r"(panic: |fatal error: |goroutine \d+ \[|thread '.*' panicked at )")
PLACEHOLDER = re.compile(r"\{(tmp|sep|fixture:([^{}]+))\}")
CASE_ID = re.compile(r"[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+")


class HarnessError(Exception):
    """The harness or a case is misconfigured, or the binary could not be run."""


class SkipCase(Exception):
    """Raised from a case's setup to skip it (for example: running as root)."""


def current_platform():
    if sys.platform == "win32":
        return "windows"
    return "linux" if sys.platform.startswith("linux") else sys.platform


# --- JSON values -------------------------------------------------------------

class Num:
    """A JSON number: compared by value, remembers its text."""
    __slots__ = ("text", "value")

    def __init__(self, text):
        self.text, self.value = text, Decimal(text)

    def __eq__(self, other):
        return isinstance(other, Num) and self.value == other.value

    def __hash__(self):
        return hash(self.value)

    def __repr__(self):
        return self.text


class Masked:
    """A value hidden by normalization. All masks are equal; the text is kept for notes."""
    __slots__ = ("text", "what")

    def __init__(self, text=None, what="number text"):
        self.text, self.what = text, what

    def __eq__(self, other):
        return isinstance(other, Masked)

    def __hash__(self):
        return 0

    def __repr__(self):
        return "<masked>"


MASK = Masked()


def _reject_constant(name):
    raise ValueError(name)


def parse_result(stdout):
    """Return the JSON object if stdout is exactly one object plus a newline, else None."""
    if not stdout.endswith(b"\n") or b"\n" in stdout[:-1]:
        return None
    try:
        value = json.loads(stdout[:-1].decode("utf-8"), parse_int=Num, parse_float=Num,
                           parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def jsonable(value):
    if isinstance(value, Num):
        return int(value.text) if re.fullmatch(r"-?\d+", value.text) else float(value.text)
    if isinstance(value, Masked):
        return "<masked>"
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


# --- Secret scanning ---------------------------------------------------------

def _aligned_needle(encode, bits_per_char, secret, pad):
    """Encoding of `secret` that is independent of its offset: drop characters that mix in
    neighbouring bytes (the `pad` bytes before it and the unknown bytes after it)."""
    total_bits = 8 * (pad + len(secret))
    text = encode(bytes(pad) + secret).decode("ascii").rstrip("=")
    skip = -(-8 * pad // bits_per_char)
    end = len(text) - (1 if total_bits % bits_per_char else 0)
    return text[skip:end]


@functools.lru_cache(maxsize=1024)
def secret_needles(secret):
    """(needle, case-fold) pairs: hex, standard and URL-safe Base64, Base32, at every alignment.
    A 64-byte identity is also searched for in each 32-byte half."""
    parts = [secret] + ([secret[:32], secret[32:]] if len(secret) == 64 else [])
    needles = []
    for part in parts:
        needles.append((part.hex().encode(), "lower"))
        for pad in range(3):
            standard = _aligned_needle(base64.b64encode, 6, part, pad)
            needles.append((standard.encode(), None))
            needles.append((standard.translate(str.maketrans("+/", "-_")).encode(), None))
        for pad in range(5):
            needles.append((_aligned_needle(base64.b32encode, 5, part, pad).encode(), "upper"))
    return needles


def contains_secret(secrets, data):
    for secret in secrets:
        for needle, fold in secret_needles(secret):
            haystack = data.lower() if fold == "lower" else data.upper() if fold == "upper" else data
            if needle and needle in haystack:
                return True
    return False


def scrub(text, secrets):
    """Replace a message that contains a secret encoding; never echo it."""
    if secrets and contains_secret(secrets, text.encode("utf-8", "surrogateescape")):
        return "[message withheld: it contains a secret encoding]"
    return text


# --- Case model --------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Expectation:
    """What a single run must show. Strings may use {sep}; paths appear as {tmp}.

    exit_code        expected exit code (None: unchecked)
    stdout           exact stdout (str is UTF-8)
    stdout_regex     re.search (MULTILINE) on stdout text
    stderr_lines     exact list of stderr lines
    stderr_regex     re.search (MULTILINE) on stderr text
    stderr_contains  substrings stderr must contain
    stderr_excludes  substrings stderr must not contain
    json             {key: value} that the JSON result must have (subset, normalized values)
    json_keys        exact key order of the JSON result
    files            {relative posix path: (size or None, unix mode or None)}: exactly the files
                     the run created (None: unchecked, {}: nothing created)
    unchanged        files that existed before the run keep their type, size, mode and content
    check            callable(ctx, observation) -> list of failure strings, for custom checks
    """
    exit_code: int | None = 0
    stdout: str | bytes | None = None
    stdout_regex: str | None = None
    stderr_lines: tuple[str, ...] | None = None
    stderr_regex: str | None = None
    stderr_contains: tuple[str, ...] = ()
    stderr_excludes: tuple[str, ...] = ()
    json: Mapping[str, object] | None = None
    json_keys: tuple[str, ...] | None = None
    files: Mapping[str, tuple[int | None, int | None]] | None = None
    unchanged: bool = True
    check: Callable | None = None


@dataclasses.dataclass(frozen=True)
class Case:
    """One black-box scenario.

    args     tokens may use {tmp}, {fixture:NAME} and {sep}
    env      extra variables on top of the scrubbed base (value None removes one)
    setup    callable(ctx) creating files in the case's temporary directory
    platforms  subset of linux/darwin/windows, or None for all
    compare  differential fields: exit, stdout (line by line), stdout_exact, json, files,
             stderr (all lines), stderr_markers (known marker lines only), sidecars (*.txt contents)
    deviation / deviation_expect  an allowed, registered difference of the candidate: the
             candidate may meet deviation_expect instead of expect (DEVIATION status)
    random_identity / attempts_nondeterministic  mask identity fields / attempts when comparing
    allow_sidecar_exports  private exports are allowed in created *.txt files only
    interact  callable(ctx, session) that drives the running process (POSIX only): wait for stderr
             lines, send signals, close stdout, wait for the exit. See Session. The run still ends
             with the ordinary observation, normalization and secret scanning.
    hold_stderr  stderr is a pipe that is filled to capacity before the start and not read until
             the process has exited, so a write by the process blocks (POSIX only)
    stdout_closed  stdout is a pipe whose read end is closed before the start, so a write by the
             process fails with a broken pipe (POSIX only)
    retries  0 or 1: a timing-based case that fails is run once more; the report says so
    """
    id: str
    description: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str | None] = dataclasses.field(default_factory=dict)
    stdin: bytes | None = None
    setup: Callable | None = None
    platforms: frozenset[str] | None = None
    timeout: float | None = None
    expect: Expectation = Expectation()
    compare: frozenset[str] = DEFAULT_COMPARE
    deviation: str | None = None
    deviation_expect: Expectation | None = None
    tags: frozenset[str] = frozenset()
    random_identity: bool = False
    attempts_nondeterministic: bool = False
    allow_sidecar_exports: bool = False
    interact: Callable | None = None
    hold_stderr: bool = False
    stdout_closed: bool = False
    retries: int = 0

    def __post_init__(self):
        if not CASE_ID.fullmatch(self.id):
            raise ValueError(f"invalid case id {self.id!r}")
        if not set(self.compare) <= COMPARE_FIELDS:
            raise ValueError(f"{self.id}: unknown compare fields {sorted(set(self.compare) - COMPARE_FIELDS)}")
        if self.platforms is not None and not set(self.platforms) <= PLATFORMS:
            raise ValueError(f"{self.id}: unknown platforms")
        if self.deviation_expect is not None and not self.deviation:
            raise ValueError(f"{self.id}: deviation_expect needs a deviation id")
        if self.retries not in (0, 1):
            raise ValueError(f"{self.id}: a case may retry at most once")
        if (self.interact or self.hold_stderr or self.stdout_closed) and self.stdin is not None:
            raise ValueError(f"{self.id}: interactive runs take no stdin")


@dataclasses.dataclass(frozen=True)
class Target:
    """A command line prefix for the program under test (a binary, or an interpreter and script)."""
    argv: tuple[str, ...]
    label: str

    @classmethod
    def from_path(cls, path):
        p = Path(path)
        if os.name == "nt" and not p.is_file() and p.with_name(p.name + ".exe").is_file():
            p = p.with_name(p.name + ".exe")
        if not p.is_file():
            raise HarnessError(f"binary not found: {path}")
        if os.name != "nt" and not os.access(p, os.X_OK):
            raise HarnessError(f"binary is not executable: {path}")
        return cls((str(p.resolve()),), p.name)


# --- Isolated execution ------------------------------------------------------

def base_env():
    names = ("PATH", "SystemRoot", "TEMP", "TMP") if os.name == "nt" else ("PATH",)
    return {name: os.environ[name] for name in names if name in os.environ}


def _kill(proc):
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)  # the child leads its own session
        else:
            proc.kill()
    except OSError:
        pass


def run_process(argv, cwd, env, stdin, timeout):
    """Run without a shell. Returns (exit code, stdout, stderr, timed_out)."""
    extra = {"start_new_session": True} if os.name == "posix" else {}
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, **extra)
    except OSError as exc:
        raise HarnessError(f"cannot execute the binary: {exc.strerror or type(exc).__name__}") from None
    try:
        out, err = proc.communicate(stdin, timeout=timeout)
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        _kill(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:  # a surviving descendant holds the pipes open
            out = err = b""
        return proc.returncode, out, err, True


# --- Interactive runs (POSIX only) -------------------------------------------

class InteractionError(Exception):
    """An interaction step failed: a line never appeared, the process died early or hung."""


def _fill_pipe(fd):
    """Fill a pipe's buffer to the brim with filler bytes; return how many were written."""
    os.set_blocking(fd, False)
    total = 0
    try:
        for chunk in (4096, 1):
            while True:
                try:
                    total += os.write(fd, b"." * chunk)
                except BlockingIOError:
                    break
    finally:
        os.set_blocking(fd, True)
    return total


class Session:
    """Handle on a running process for Case.interact callables.

    A pump thread reads stdout and stderr as they arrive, so the pipes never fill; stderr is split
    into lines that wait_line can wait for. Timeouts are in seconds; a failed wait raises InteractionError.
    """

    def __init__(self, proc, out_fd, err_fd):
        self.proc = proc
        self.out, self.err = bytearray(), bytearray()
        self._lines, self._cursor, self._partial = [], 0, b""
        self._cond = threading.Condition()
        self._thread = threading.Thread(target=self._pump, args=(out_fd, err_fd), daemon=True)
        self._thread.start()

    def _pump(self, out_fd, err_fd):
        sel = selectors.DefaultSelector()
        streams = {}
        for fd, name in ((out_fd, "out"), (err_fd, "err")):
            if fd is not None:
                sel.register(fd, selectors.EVENT_READ, name)
                streams[name] = fd
        try:
            while streams:
                for key, _ in sel.select():
                    data = os.read(key.fd, 65536)
                    if not data:
                        sel.unregister(key.fd)
                        os.close(key.fd)
                        del streams[key.data]
                    elif key.data == "out":
                        self.out += data
                    else:
                        with self._cond:
                            self.err += data
                            *complete, self._partial = (self._partial + data).split(b"\n")
                            self._lines += [line.decode("utf-8", "surrogateescape") for line in complete]
                            self._cond.notify_all()
        finally:
            sel.close()
            with self._cond:
                if self._partial:
                    self._lines.append(self._partial.decode("utf-8", "surrogateescape"))
                    self._partial = b""
                self._cond.notify_all()

    def join_pump(self, timeout=5.0):
        self._thread.join(timeout)  # a descendant that keeps the pipes open is left to the daemon thread

    def stderr_lines(self):
        """The complete stderr lines received so far."""
        with self._cond:
            return list(self._lines)

    def wait_line(self, pattern, timeout=60.0):
        """Wait for the next stderr line, after the one the previous wait matched, that starts with
        `pattern` (a str) or matches it (a compiled regex). Returns the line."""
        text = getattr(pattern, "pattern", pattern)
        match = pattern.search if hasattr(pattern, "search") else (lambda line: line.startswith(pattern))
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for i in range(self._cursor, len(self._lines)):
                    if match(self._lines[i]):
                        self._cursor = i + 1
                        return self._lines[i]
                if not self._thread.is_alive():
                    raise InteractionError(f"stderr closed (exit code {self.proc.poll()}) before the line "
                                           f"{text!r} appeared")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise InteractionError(f"no line {text!r} within {timeout:g} s; last lines: "
                                           f"{[line[:60] for line in self._lines[-3:]]}")
                self._cond.wait(min(remaining, 0.1))

    def signal(self, signum):
        """Send a signal to the process, which must still be running."""
        if self.proc.poll() is not None:
            raise InteractionError(f"cannot send signal {int(signum)}: the process exited with code "
                                   f"{self.proc.returncode}")
        os.kill(self.proc.pid, signum)

    def wait_exit(self, timeout):
        """Wait for the process to exit and return its exit code."""
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            raise InteractionError(f"the process did not exit within {timeout:g} s") from None


def run_interactive(argv, cwd, env, timeout, interact, ctx, hold_stderr, stdout_closed):
    """Like run_process, but `interact(ctx, session)` drives the process while it runs. The timeout
    bounds the process once the interaction has ended; the interaction's own waits have timeouts.
    With hold_stderr, stderr is a pipe filled to capacity before the start and read only after the exit.
    With stdout_closed, stdout is a pipe without a reader: a write by the process breaks it.
    Returns (exit code, stdout, stderr, timed_out, interaction problem or None)."""
    if os.name != "posix":
        raise HarnessError("interactive runs are POSIX only")
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    filler = _fill_pipe(err_w) if hold_stderr else 0
    if stdout_closed:
        os.close(out_r)
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out_w, stderr=err_w,
                                start_new_session=True)
    except OSError as exc:
        for fd in (out_w, err_r, err_w, *([] if stdout_closed else [out_r])):
            os.close(fd)
        raise HarnessError(f"cannot execute the binary: {exc.strerror or type(exc).__name__}") from None
    os.close(out_w)
    os.close(err_w)
    session = Session(proc, None if stdout_closed else out_r, None if hold_stderr else err_r)
    problem, timed_out = None, False
    try:
        if interact is not None:
            try:
                interact(ctx, session)
            except InteractionError as exc:
                problem = f"(interaction) {exc}"
        try:
            proc.wait(0 if problem else timeout)
        except subprocess.TimeoutExpired:
            timed_out = problem is None
    finally:
        if proc.poll() is None:  # also reaches descendants: the child leads its own session
            _kill(proc)
            proc.wait()
        session.join_pump()
    err = bytes(session.err)
    if hold_stderr:
        os.set_blocking(err_r, False)
        data = bytearray()
        while True:
            try:
                chunk = os.read(err_r, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            data += chunk
        os.close(err_r)
        err = bytes(data)[filler:]
    return proc.returncode, bytes(session.out), err, timed_out, problem


def _entry(path, with_digest):
    info = os.lstat(path)
    mode = None if os.name == "nt" else stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        entry = {"type": "symlink", "size": None, "mode": mode, "target": os.readlink(path)}
    elif stat.S_ISDIR(info.st_mode):
        entry = {"type": "dir", "size": None, "mode": mode}
    elif stat.S_ISREG(info.st_mode):
        entry = {"type": "file", "size": info.st_size, "mode": mode}
        if with_digest:
            try:  # never open FIFOs or devices: only regular files are hashed
                with open(path, "rb") as f:
                    entry["digest"] = hashlib.sha256(f.read(16 << 20)).hexdigest()
            except OSError:
                pass
    else:
        entry = {"type": "fifo" if stat.S_ISFIFO(info.st_mode) else "other", "size": None, "mode": mode}
    return entry


def snapshot(root):
    """{relative posix path: entry} for everything under root (symlinks are not followed)."""
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath, name)
            try:
                found[path.relative_to(root).as_posix()] = _entry(path, True)
            except OSError:
                pass
    return found


def _public(entry):
    return {k: v for k, v in entry.items() if k != "digest"}


def _remove_tree(path):
    def onexc(func, target, exc):
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            func(target)
        except OSError:
            pass
    if os.name == "posix":  # cases may leave directories unwritable
        stack = [path]
        while stack:
            try:
                directory = stack.pop()
                if stat.S_ISDIR(os.lstat(directory).st_mode):
                    os.chmod(directory, 0o700)
                    with os.scandir(directory) as it:
                        stack.extend(e.path for e in it if e.is_dir(follow_symlinks=False))
            except OSError:
                pass
    shutil.rmtree(path, onexc=onexc)


def _inside(path, parent):
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


class Context:
    """One run's working directory and secrets, handed to setup and check callables.

    target  the binary under test; peer  the other binary in differential mode (else the same one)
    """

    def __init__(self, role, target, peer):
        self.role, self.target, self.peer = role, target, peer
        self.secrets, self.fixtures = [], {}
        raw = tempfile.mkdtemp(prefix="lxmf-conf-")  # mode 0700 on Unix
        self.tmp = Path(raw).resolve()
        self.tmp_names = {raw, str(self.tmp)}
        if _inside(self.tmp, REPO_ROOT):
            self.dispose()
            raise HarnessError("the temporary directory is inside the repository; set TMPDIR elsewhere")

    def path(self, relative):
        return self.tmp / relative

    def mkdir(self, relative, mode=0o700):
        path = self.path(relative)
        path.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(path, mode)
        return path

    def write(self, relative, data, mode=None, secret=False):
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if mode is not None and os.name != "nt":
            os.chmod(path, mode)
        if secret:
            self.add_secret(data)
        return path

    def add_secret(self, data):
        if len(data) < MIN_SECRET_BYTES:
            raise HarnessError("a secret must have at least 8 bytes to be scanned reliably")
        if data not in self.secrets:
            self.secrets.append(bytes(data))

    def add_fixture(self, name, path):
        self.fixtures[name] = Path(path)

    def expand(self, text):
        def substitute(match):
            if match[1] == "tmp":
                return str(self.tmp)
            if match[1] == "sep":
                return os.sep
            try:
                return str(self.fixtures[match[2]])
            except KeyError:
                raise HarnessError(f"unknown fixture {match[2]!r}") from None
        return PLACEHOLDER.sub(substitute, text)

    def dispose(self, keep_at=None):
        try:
            if keep_at is not None:
                keep_at.parent.mkdir(parents=True, exist_ok=True)
                if keep_at.exists():
                    _remove_tree(keep_at)
                shutil.move(self.tmp, keep_at)
        except (OSError, shutil.Error) as exc:
            print(f"warning: could not keep {self.tmp}: {type(exc).__name__}", file=sys.stderr)
        if self.tmp.exists():
            _remove_tree(self.tmp)


# --- Observation and normalization -------------------------------------------

@dataclasses.dataclass
class Observation:
    exit_code: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    json: dict | None
    files: list  # entries created by the run: {"path", "type", "size", "mode"[, "target"]}
    changes: list  # setup files the run changed or removed, as "modified <path>" / "removed <path>"
    texts: dict  # contents of created *.txt files


@dataclasses.dataclass
class Normalized:
    exit_code: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    stderr_lines: list
    markers: list
    json: dict | None
    problems: list
    files: list
    changes: list
    texts: dict
    leaked: bool = False


def split_lines(data):
    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", "surrogateescape") for p in parts]


def _tmp_variants(ctx):
    variants = set(ctx.tmp_names)
    if os.name == "nt":
        variants |= {v.replace("\\", "\\\\") for v in variants}
    return sorted(variants, key=len, reverse=True)


def _replace_tmp(value, variants):
    if isinstance(value, str):
        for variant in variants:
            value = value.replace(variant, "{tmp}")
        return value
    if isinstance(value, dict):
        return {k: _replace_tmp(v, variants) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_tmp(v, variants) for v in value]
    return value


def _normalize_json(obj, case, variants):
    problems = []
    parts = [obj.get(k) for k in ("x25519_public", "ed25519_public", "public_key")]
    if all(isinstance(p, str) for p in parts) and parts[0] + parts[1] != parts[2]:
        problems.append("public_key is not x25519_public + ed25519_public")
    result = {}
    for key, value in obj.items():
        value = _replace_tmp(value, variants)
        if key == "elapsed_seconds":
            if not (isinstance(value, Num) and value.value >= 0):
                problems.append("elapsed_seconds is not a number >= 0")
            value = Masked(value.text if isinstance(value, Num) else None)
        elif key == "version":
            if not (isinstance(value, str) and value):
                problems.append("version is not a non-empty string")
            value = Masked(value if isinstance(value, str) and value else None, "version")
        elif key == "attempts" and case.attempts_nondeterministic:
            value = Masked(value.text if isinstance(value, Num) else None)
        elif key in HEX_LENGTHS:
            if not (isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{HEX_LENGTHS[key]}}}", value)):
                problems.append(f"{key} is not lowercase hex of length {HEX_LENGTHS[key]}")
            if case.random_identity:
                value = MASK
        result[key] = value
    return result, problems


def normalize(case, ctx, obs):
    variants = _tmp_variants(ctx)
    raw = [os.fsencode(v) for v in variants]

    def clean(data):
        for needle in raw:
            data = data.replace(needle, b"{tmp}")
        return data

    value, problems = (None, []) if obs.json is None else _normalize_json(obs.json, case, variants)
    stderr = clean(obs.stderr)
    lines = split_lines(stderr)
    return Normalized(
        exit_code=obs.exit_code, timed_out=obs.timed_out, stdout=clean(obs.stdout), stderr=stderr,
        stderr_lines=lines, markers=[line for line in lines if MARKER_LINE.match(line)], json=value,
        problems=problems, files=[{**f, "target": _replace_tmp(f["target"], variants)} if "target" in f else f
                                  for f in obs.files],
        changes=list(obs.changes), texts={k: clean(v) for k, v in obs.texts.items()})


# --- Running one side --------------------------------------------------------

@dataclasses.dataclass
class Run:
    ctx: Context
    obs: Observation
    norm: Normalized
    invariants: list


def _scan(case, ctx, obs):
    streams = {"stdout": obs.stdout, "stderr": obs.stderr}
    if obs.json is not None:
        streams["json"] = "\n".join(_strings(obs.json)).encode("utf-8", "surrogateescape")
    if not case.allow_sidecar_exports:
        streams.update({f"sidecar {name}": data for name, data in obs.texts.items()})
    return [f"secret encoding found in {name}" for name, data in streams.items()
            if contains_secret(ctx.secrets, data)]


def _execute(case, role, target, peer, default_timeout):
    ctx = Context(role, target, peer)
    try:
        if case.setup:
            case.setup(ctx)
        before = snapshot(ctx.tmp)
        argv = [*target.argv, *(ctx.expand(a) for a in case.args)]
        env = base_env()
        for key, value in case.env.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = ctx.expand(value)
        timeout = case.timeout or default_timeout
        problem = None
        if case.interact or case.hold_stderr or case.stdout_closed:
            code, out, err, timed_out, problem = run_interactive(
                argv, ctx.tmp, env, timeout, case.interact, ctx, case.hold_stderr, case.stdout_closed)
        else:
            code, out, err, timed_out = run_process(argv, ctx.tmp, env, case.stdin, timeout)
        after = snapshot(ctx.tmp)
        created = sorted(p for p in after if p not in before)
        files = [{"path": p, **_public(after[p])} for p in created]
        changes = [f"modified {p}" for p in sorted(before) if p in after and before[p] != after[p]]
        changes += [f"removed {p}" for p in sorted(before) if p not in after]
        texts = {}
        for p in created:
            entry = after[p]
            if entry["type"] != "file":
                continue
            if entry["size"] == 64 and not p.endswith(".txt"):  # an identity file the binary wrote
                ctx.add_secret((ctx.tmp / p).read_bytes())
            elif p.endswith(".txt") and entry["size"] <= MAX_TEXT:
                texts[p] = (ctx.tmp / p).read_bytes()
        obs = Observation(code, timed_out, out, err, parse_result(out), files, changes, texts)
        norm = normalize(case, ctx, obs)
        invariants = [problem] if problem else []
        if timed_out:
            invariants.append(f"(timeout) the process was killed after {timeout:g} s")
        invariants += norm.problems
        invariants += [f"crash marker in stderr: {line[:60]!r}" for line in norm.stderr_lines
                       if CRASH_LINE.match(line)][:1]
        hits = _scan(case, ctx, obs)
        norm.leaked = bool(hits)
        invariants += hits
        return Run(ctx, obs, norm, invariants)
    except BaseException:
        ctx.dispose()
        raise


# --- Expectations and comparison ----------------------------------------------

def _short(value, limit=160):
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _text(data):
    return data.decode("utf-8", "surrogateescape")


def _sep(value):
    if isinstance(value, str):
        return value.replace("{sep}", os.sep)
    if isinstance(value, dict):
        return {k: _sep(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sep(v) for v in value]
    return value


def _same(actual, expected):
    if isinstance(actual, Masked) or isinstance(expected, Masked):
        return isinstance(actual, Masked) and isinstance(expected, Masked)
    if isinstance(actual, Num):
        return (isinstance(expected, (int, float, Decimal, Num)) and not isinstance(expected, bool)
                and actual.value == (expected.value if isinstance(expected, Num) else Decimal(str(expected))))
    if isinstance(actual, dict):
        return (isinstance(expected, dict) and list(actual) == list(expected)
                and all(_same(actual[k], expected[k]) for k in actual))
    if isinstance(actual, list):
        return (isinstance(expected, (list, tuple)) and len(actual) == len(expected)
                and all(_same(a, e) for a, e in zip(actual, expected)))
    return type(actual) is type(expected) and actual == expected


def check_expectation(exp, ctx, obs, norm):
    """Failure strings for one run against an Expectation (empty: it holds)."""
    fails = []
    if exp.exit_code is not None and norm.exit_code != exp.exit_code:
        fails.append(f"exit code {norm.exit_code}, expected {exp.exit_code}")
    if exp.stdout is not None:
        want = exp.stdout if isinstance(exp.stdout, bytes) else _sep(exp.stdout).encode("utf-8", "surrogateescape")
        if norm.stdout != want:
            fails.append(f"stdout differs from the expected text: got {_short(_text(norm.stdout))}")
    if exp.stdout_regex is not None and not re.search(exp.stdout_regex, _text(norm.stdout), re.MULTILINE):
        fails.append(f"stdout does not match {exp.stdout_regex!r}: got {_short(_text(norm.stdout))}")
    if exp.stderr_lines is not None and norm.stderr_lines != _sep(list(exp.stderr_lines)):
        fails.append(f"stderr lines {_short(norm.stderr_lines)}, expected {_short(list(exp.stderr_lines))}")
    if exp.stderr_regex is not None and not re.search(exp.stderr_regex, _text(norm.stderr), re.MULTILINE):
        fails.append(f"stderr does not match {exp.stderr_regex!r}: got {_short(_text(norm.stderr))}")
    for needle in exp.stderr_contains:
        if _sep(needle) not in _text(norm.stderr):
            fails.append(f"stderr lacks {needle!r}")
    for needle in exp.stderr_excludes:
        if _sep(needle) in _text(norm.stderr):
            fails.append(f"stderr contains {needle!r}")
    if exp.json is not None or exp.json_keys is not None:
        if norm.json is None:
            fails.append("stdout is not one JSON object followed by a newline")
        else:
            if exp.json_keys is not None and list(norm.json) != list(exp.json_keys):
                fails.append(f"JSON keys {list(norm.json)}, expected {list(exp.json_keys)}")
            for key, want in (exp.json or {}).items():
                if key not in norm.json:
                    fails.append(f"JSON key {key!r} is missing")
                elif not _same(norm.json[key], _sep(want)):
                    fails.append(f"JSON {key}: got {_short(norm.json[key])}, expected {_short(want)}")
    if exp.files is not None:
        got = {f["path"]: f for f in norm.files}
        for path in sorted(set(got) ^ set(exp.files)):
            fails.append(f"created file {path!r} " + ("was not expected" if path in got else "is missing"))
        for path, (size, mode) in ((p, v) for p, v in exp.files.items() if p in got):
            if size is not None and got[path]["size"] != size:
                fails.append(f"{path}: size {got[path]['size']}, expected {size}")
            if mode is not None and got[path]["mode"] is not None and got[path]["mode"] != mode:
                fails.append(f"{path}: mode {got[path]['mode']:04o}, expected {mode:04o}")
    if exp.unchanged:
        fails += [f"input file changed: {change}" for change in norm.changes]
    if exp.check is not None:
        try:
            fails += list(exp.check(ctx, obs) or [])
        except Exception as exc:  # a broken check is a failure, not a crash of the run
            fails.append(f"check raised {type(exc).__name__}")
    return fails


def _cmp_json(a, b, path, diffs, notes):
    if isinstance(a, dict) and isinstance(b, dict):
        if list(a) != list(b):
            kind = "key order differs" if set(a) == set(b) else "keys differ"
            diffs.append(f"json {path}: {kind}: reference {list(a)}, candidate {list(b)}")
        for key in a:
            if key in b:
                _cmp_json(a[key], b[key], f"{path}.{key}", diffs, notes)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            diffs.append(f"json {path}: length {len(a)} (reference) vs {len(b)} (candidate)")
        for i, (x, y) in enumerate(zip(a, b)):
            _cmp_json(x, y, f"{path}[{i}]", diffs, notes)
    elif isinstance(a, (Num, Masked)) and type(a) is type(b):
        if a != b:
            diffs.append(f"json {path}: reference {a!r}, candidate {b!r}")
        elif a.text is not None and b.text is not None and a.text != b.text:
            what = getattr(a, "what", "number text")  # Num has no label
            tail = "only its presence is compared" if what == "version" else "values are equal"
            notes.append(f"json {path}: {what} differs ({a.text} vs {b.text}); {tail}")
    elif type(a) is not type(b) or a != b:
        diffs.append(f"json {path}: reference {_short(a)}, candidate {_short(b)}")


def _cmp_lines(name, a, b, diffs):
    for i in range(max(len(a), len(b))):
        x, y = (a[i] if i < len(a) else "<missing>"), (b[i] if i < len(b) else "<missing>")
        if x != y:
            diffs.append(f"{name} line {i + 1}: reference {_short(x)}, candidate {_short(y)}")
            return


def compare(case, ref, cand):
    """(differences, notes) between two normalized observations, for the fields in case.compare."""
    diffs, notes, fields = [], [], case.compare
    if "exit" in fields and ref.exit_code != cand.exit_code:
        diffs.append(f"exit code: reference {ref.exit_code}, candidate {cand.exit_code}")
    if "json" in fields:
        if (ref.json is None) != (cand.json is None):
            diffs.append("json: only one of the runs printed a single JSON object")
        elif ref.json is not None:
            _cmp_json(ref.json, cand.json, "$", diffs, notes)
    if "stdout_exact" in fields and ref.stdout != cand.stdout:
        offset = next((i for i, (x, y) in enumerate(zip(ref.stdout, cand.stdout)) if x != y),
                      min(len(ref.stdout), len(cand.stdout)))
        diffs.append(f"stdout bytes differ at offset {offset} (lengths {len(ref.stdout)} and {len(cand.stdout)})")
    if "stdout" in fields:
        _cmp_lines("stdout", split_lines(ref.stdout), split_lines(cand.stdout), diffs)
    if "stderr" in fields:
        _cmp_lines("stderr", ref.stderr_lines, cand.stderr_lines, diffs)
    if "stderr_markers" in fields:
        _cmp_lines("stderr marker", ref.markers, cand.markers, diffs)
    if "files" in fields:
        a, b = {f["path"]: f for f in ref.files}, {f["path"]: f for f in cand.files}
        for path in sorted(set(a) ^ set(b)):
            diffs.append(f"created file {path!r} only in the " + ("reference" if path in a else "candidate"))
        for path in sorted(set(a) & set(b)):
            for attr in ("type", "size", "mode", "target"):
                x, y = a[path].get(attr), b[path].get(attr)
                if x != y and not (attr == "mode" and (x is None or y is None)):
                    diffs.append(f"{path}: {attr} reference {x!r}, candidate {y!r}")
        if ref.changes != cand.changes:
            diffs.append(f"changed input files: reference {ref.changes}, candidate {cand.changes}")
    if "sidecars" in fields:
        for path in sorted(set(ref.texts) | set(cand.texts)):
            if ref.texts.get(path) != cand.texts.get(path):
                diffs.append(f"contents of {path!r} differ (withheld)")
    return diffs, notes


# --- Case results -------------------------------------------------------------

@dataclasses.dataclass
class CaseResult:
    id: str
    status: str  # PASS, FAIL, SKIP or DEVIATION
    deviation: str | None = None
    failures: list = dataclasses.field(default_factory=list)
    notes: list = dataclasses.field(default_factory=list)
    candidate: Normalized | None = None
    reference: Normalized | None = None
    retried: bool = False  # the case failed once and was run again (Case.retries)


def _observation_report(norm):
    if norm is None:
        return None
    withheld = "[withheld: a secret encoding was found]"
    return {
        "exit_code": norm.exit_code, "timed_out": norm.timed_out,
        "stdout": withheld if norm.leaked else _text(norm.stdout)[:MAX_REPORT_TEXT],
        "stderr": withheld if norm.leaked else _text(norm.stderr)[:MAX_REPORT_TEXT],
        "json": None if norm.json is None or norm.leaked else jsonable(norm.json),
        "files": norm.files, "changes": norm.changes,
    }


def build_report(results, mode, binary, reference):
    """JSON-serializable report. Sidecar contents and identity files are never included."""
    counts = {s: sum(r.status == s for r in results) for s in ("PASS", "FAIL", "SKIP", "DEVIATION")}
    return {
        "mode": mode, "binary": binary, "reference": reference,
        "platform": {"os": current_platform(), "machine": os.uname().machine if hasattr(os, "uname") else None,
                     "python": sys.version.split()[0]},
        "summary": counts,
        "cases": [{"id": r.id, "status": r.status, "deviation": r.deviation, "retried": r.retried, "exit_code":
                   None if r.candidate is None else r.candidate.exit_code,
                   "failures": r.failures, "notes": r.notes,
                   "observation": _observation_report(r.candidate),
                   "reference_observation": _observation_report(r.reference)} for r in results],
    }


def run_case(case, target, reference=None, *, default_timeout=DEFAULT_TIMEOUT, keep_failed=None):
    """Run one case in single mode (reference None) or differential mode. Never raises.
    A failed case with retries=1 runs once more; a pass on the second run is reported with a note."""
    if not case.retries:
        return _run_case_once(case, target, reference, default_timeout, keep_failed)
    first = _run_case_once(case, target, reference, default_timeout, None)
    if first.status != "FAIL":
        return first
    second = _run_case_once(case, target, reference, default_timeout, keep_failed)
    second.retried = True
    second.notes.insert(0, "retry used; the first run failed: " + "; ".join(first.failures[:3]))
    return second


def _run_case_once(case, target, reference, default_timeout, keep_failed):
    here = current_platform()
    if case.platforms is not None and here not in case.platforms:
        return CaseResult(case.id, "SKIP", notes=[f"platform {here} is not in {sorted(case.platforms)}"])
    runs = {}
    secrets = []
    result = CaseResult(case.id, "FAIL")
    try:
        try:
            if reference is not None:
                runs["reference"] = _execute(case, "reference", reference, target, default_timeout)
            runs["candidate"] = _execute(case, "candidate", target, reference or target, default_timeout)
        except SkipCase as exc:
            result.status, result.notes = "SKIP", [str(exc) or "skipped by the case"]
            return result
        except Exception as exc:  # setup bugs and unrunnable binaries fail this case only
            secrets = [s for run in runs.values() for s in run.ctx.secrets]
            result.failures = [scrub(f"error: {_describe(exc)}", secrets)]
            return result
        secrets = [s for run in runs.values() for s in run.ctx.secrets]
        try:
            _judge(case, runs, result)
        except Exception as exc:  # a harness bug must not abort the whole run
            result.status, result.failures = "FAIL", [f"harness error: {_describe(exc)}"]
        result.failures = [scrub(f, secrets) for f in result.failures]
        result.notes = [scrub(n, secrets) for n in result.notes]
        return result
    finally:
        for role, run in runs.items():
            failed = result.status == "FAIL" and keep_failed is not None
            run.ctx.dispose(Path(keep_failed) / case.id / role if failed else None)


def _describe(exc):
    return f"{type(exc).__name__}: {exc}"[:200]


def _judge(case, runs, result):
    cand = runs["candidate"]
    ref = runs.get("reference")
    result.candidate = cand.norm
    result.reference = ref.norm if ref else None
    prefixed = (lambda who, items: [f"{who}: {i}" for i in items]) if ref else (lambda who, items: items)
    invariant = prefixed("candidate", cand.invariants) + (prefixed("reference", ref.invariants) if ref else [])
    cand_fails = check_expectation(case.expect, cand.ctx, cand.obs, cand.norm)
    ref_fails, diffs = [], []
    if ref:
        ref_fails = check_expectation(case.expect, ref.ctx, ref.obs, ref.norm)
        diffs, result.notes = compare(case, ref.norm, cand.norm)
    if invariant or ref_fails:
        result.failures = invariant + prefixed("reference", ref_fails)
        return
    if not cand_fails and not diffs:
        result.status = "PASS"
        if case.deviation:
            result.notes.append(f"declared deviation {case.deviation} was not observed")
        return
    if case.deviation and (ref or case.deviation_expect):
        dev_fails = (check_expectation(case.deviation_expect, cand.ctx, cand.obs, cand.norm)
                     if case.deviation_expect else [])
        if not dev_fails:
            result.status, result.deviation = "DEVIATION", case.deviation
            return
        result.failures = prefixed("candidate", dev_fails)
        return
    result.failures = prefixed("candidate", cand_fails) + diffs


def select_cases(cases, patterns):
    """Cases whose id matches any glob (all when patterns is empty)."""
    return [c for c in cases if not patterns or any(fnmatch.fnmatchcase(c.id, p) for p in patterns)]


# --- Cross-inspection ---------------------------------------------------------

def inspect_with(binary, path, timeout=30.0):
    """Run `--inspect PATH --json` with `binary` and return its public fields."""
    target = binary if isinstance(binary, Target) else Target.from_path(binary)
    with tempfile.TemporaryDirectory(prefix="lxmf-inspect-") as cwd:
        code, out, _, timed_out = run_process([*target.argv, "--inspect", os.path.abspath(path), "--json"],
                                              cwd, base_env(), None, timeout)
    result = parse_result(out)
    if timed_out or code != 0 or result is None or result.get("status") != "inspected":
        raise HarnessError(f"{target.label} could not inspect the file (exit {code})")
    return {name: result[name] for name in PUBLIC_FIELDS}
