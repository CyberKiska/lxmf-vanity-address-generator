"""Inspection and protocol cases: exact public output for the 131-vector corpus and the golden vector,
filename quoting, and every rejection of --inspect. Public fixtures only; identity files are built at
run time in the case's temporary directory (see conformance/fixtures.py).

Ids: protocol.corpus.* (131 vectors x masked/raw x text/json), protocol.golden.*, inspect.names.*,
inspect.reject.*, inspect.unchanged.*. Inspection never writes: every run expects files={} and
unchanged inputs, and a check that exactly the one input file exists.
"""

import os
import re
import stat

from conformance import fixtures
from conformance.harness import Case, Expectation, Num, SkipCase, current_platform

CASES = []
NON_WINDOWS = frozenset({"linux", "darwin"})
LINUX = frozenset({"linux"})
SUCCESS_COMPARE = frozenset({"exit", "json", "stdout_exact", "files", "stderr"})
FIXED_ERROR_COMPARE = frozenset({"exit", "json", "stdout_exact", "files", "stderr"})
OS_ERROR_COMPARE = frozenset({"exit", "files"})  # the operating system's words may differ between implementations
ON_WINDOWS = current_platform() == "windows"
OTHER = fixtures.vectors()[0]  # valid identity used as the content of rejected inputs


def only_file(name):
    """The case's directory holds exactly the input file: inspection created nothing."""
    def check(ctx, obs):
        names = sorted(os.listdir(ctx.tmp))
        return [] if names == [name] else [f"directory holds {len(names)} entries, expected only the input"]
    return check


def entries(*names):
    def check(ctx, obs):
        found = sorted(os.listdir(ctx.tmp))
        return [] if found == sorted(names) else [f"directory entries {found}, expected {sorted(names)}"]
    return check


def success(identity, file_name, text, masked, extra_check=None):
    warning = () if masked or identity.raw == identity.private else (fixtures.UNMASKED_WARNING,)

    def check(ctx, obs):
        fails = only_file(file_name)(ctx, obs) if extra_check is None else extra_check(ctx, obs)
        return fails + (fixtures.verify_py_failures(obs.stdout, identity) if text else [])

    if text:
        return Expectation(exit_code=0, files={}, stdout=fixtures.inspection_text(identity, file_name),
                           stderr_lines=warning, check=check)
    return Expectation(exit_code=0, files={}, stderr_lines=warning, stdout_regex=fixtures.inspection_json_regex(identity),
                       json={"status": "inspected", **fixtures.identity_fields(identity), "attempts": 0,
                             "generator": "segmented"},
                       check=lambda ctx, obs: check(ctx, obs) + ([] if obs.json["elapsed_seconds"] == Num("0")
                                                                  else ["elapsed_seconds is not 0"]))


def add_success(cid, description, identity, masked, file_name, text, *, platforms=None, path=None, extra_check=None,
                setup=None):
    def setup_file(ctx):
        fixtures.write_identity(ctx, file_name, identity, masked)
        if setup:
            setup(ctx)

    target = path or f"{{tmp}}{{sep}}{file_name}"
    args = ("--inspect", target) if text else ("--inspect", target, "--json")
    CASES.append(Case(id=cid, description=description, args=args, setup=setup_file, platforms=platforms,
                      expect=success(identity, os.path.basename(file_name), text, masked, extra_check),
                      compare=SUCCESS_COMPARE))


# --- Corpus: 131 vectors, masked and raw, text and JSON ---------------------------------------------------

for _identity in fixtures.vectors():
    for _form, _masked in (("masked", True), ("raw", False)):
        for _mode, _text in (("text", True), ("json", False)):
            add_success(f"protocol.corpus.{_identity.name}.{_form}.{_mode}",
                        f"{_identity.name}: {_form} input, {_mode} output is exact", _identity, _masked,
                        f"identity-{_identity.name}", _text)

# --- Golden vector ----------------------------------------------------------------------------------------

for _form, _masked in (("masked", True), ("raw", False)):
    for _mode, _text in (("text", True), ("json", False)):
        add_success(f"protocol.golden.{_form}.{_mode}", f"golden vector: {_form} input, {_mode} output is exact",
                    fixtures.golden(), _masked, "golden-public-fixture", _text)

# --- File names: Go %q quoting of the base name -----------------------------------------------------------

NAMES = (  # (id, file name, platforms)
    ("space", "my identity", None),
    ("unicode", "naïve-日本語-\U0001f642", None),
    ("single_quote", "it's", None),
    ("double_quote", 'say "hi"', NON_WINDOWS),
    ("backslash", "back\\slash", NON_WINDOWS),
    ("tab", "tab\there", NON_WINDOWS),
    ("newline", "line\nbreak", NON_WINDOWS),
    ("del", "del\x7fname", NON_WINDOWS),
    ("bell", "bell\x07name", NON_WINDOWS),
    ("invalid_utf8", "bad\udcffbyte", LINUX),  # macOS file systems refuse invalid UTF-8 names
)
for _id, _name, _platforms in NAMES:
    add_success(f"inspect.names.{_id}", f"the base name {_name!r} is shown quoted like Go's %q", fixtures.golden(), True,
                _name, True, platforms=_platforms)
add_success("inspect.names.raw_input_with_space", "an unmasked input keeps the quoting and the warning", fixtures.vectors()[1],
            False, "my identity", True)
add_success("inspect.names.only_base_name", "only the base name is printed, not the directory", fixtures.golden(), True,
            "deep dir/inner dir/key file", True, path="{tmp}{sep}deep dir{sep}inner dir{sep}key file",
            extra_check=entries("deep dir"))
add_success("inspect.names.relative_dotdot_cleaned", "a relative path with .. is cleaned lexically; its base name is shown",
            fixtures.golden(), True, "a/key", True, path=f"a{os.sep}b{os.sep}..{os.sep}key",
            setup=lambda ctx: ctx.mkdir("a/b"), extra_check=entries("a"))


# --- Rejections ---------------------------------------------------------------------------------------------

def failure(prefix=None, exact=None):
    """Exit 1, status failed, an error that is `exact` or starts with `prefix`, nothing created."""
    wanted = exact if exact is not None else prefix

    def check(ctx, obs):
        if obs.json is None:  # text mode
            return []
        error = obs.json.get("error")
        if not isinstance(error, str) or not error:
            return ["the JSON result has no error text"]
        if exact is not None and error != exact or prefix is not None and not error.startswith(prefix):
            return [f"error text {error[:80]!r} does not start with the expected message"]
        return []

    return check, wanted


def add_reject(cid, description, args, setup=None, *, message=None, prefix=None, platforms=None, timeout=None,
               listing=None):
    """One rejection in JSON mode and one in text mode. `message` is exact; `prefix` is a stable start."""
    check, wanted = failure(prefix, message)
    fixed = message is not None
    for mode, extra in (("json", ("--json",)), ("text", ())):
        def final_check(ctx, obs, check=check):
            fails = check(ctx, obs)
            if listing is not None:
                fails += entries(*listing)(ctx, obs)
            return fails
        if mode == "json":
            expect = Expectation(exit_code=1, files={}, check=final_check, json={"status": "failed"},
                                 stderr_regex=r"\AError: " + re.escape(wanted) if wanted else None)
            if fixed:
                expect = Expectation(exit_code=1, files={}, check=final_check, json={"status": "failed", "error": message},
                                     stderr_lines=(f"Error: {message}",))
        else:
            expect = Expectation(exit_code=1, files={}, check=final_check, stdout=b"",
                                 stderr_regex=r"\AError: " + re.escape(wanted or "") + (r"\n\Z" if fixed else ""))
        CASES.append(Case(id=f"inspect.reject.{cid}.{mode}", description=f"{description} ({mode} mode)",
                          args=("--inspect", *args, *extra), setup=setup, platforms=platforms, timeout=timeout,
                          expect=expect, compare=FIXED_ERROR_COMPARE if fixed else OS_ERROR_COMPARE))


def register(ctx, identity=OTHER):
    ctx.add_secret(identity.private)
    ctx.add_secret(identity.raw)


def sized(data_for):
    def setup(ctx):
        register(ctx)
        ctx.write("input", data_for(OTHER.private))
    return setup


NOT_64 = "inspection input must be a regular file of exactly 64 bytes"
NOT_REGULAR = "inspection input must be a regular file"
for _size, _make in ((0, lambda p: b""), (1, lambda p: p[:1]), (63, lambda p: p[:63]), (65, lambda p: p + b"\x00"),
                     (4096, lambda p: p * 64)):
    add_reject(f"size_{_size}", f"a file of {_size} bytes is not an identity", ("input",), sized(_make), message=NOT_64,
               listing=("input",))


def make_directory(ctx):
    register(ctx)
    ctx.mkdir("folder")


add_reject("directory", "a directory is not a regular file", ("folder",), make_directory, message=NOT_REGULAR,
           listing=("folder",))

# A missing file: Go's os.Root reports "statat <name>: ..." on Unix; Windows words differ.
add_reject("missing_file", "a missing file in an existing directory", ("absent",), register,
           prefix=None if ON_WINDOWS else "statat absent: ", listing=())
add_reject("missing_parent", "a missing parent directory", (f"nodir{os.sep}input",), register,
           prefix="open output directory: ", listing=())
add_reject("missing_parent_absolute", "a missing absolute parent directory", ("{tmp}{sep}nodir{sep}input",), register,
           prefix="open output directory: ", listing=())

MUST_NAME = "output path must name a file"


def with_files(ctx):
    register(ctx)
    ctx.write("input", OTHER.private)
    ctx.mkdir("sub")


for _id, _arg in (("dot", "."), ("dotdot", ".."), ("abs_dot", "{tmp}{sep}."), ("abs_dotdot", "{tmp}{sep}.."),
                  ("trailing_sep", "{tmp}{sep}"), ("sub_dot", "sub{sep}."), ("sub_dotdot", "sub{sep}.."),
                  ("sub_trailing_sep", "sub{sep}"), ("file_trailing_sep", "input{sep}"), ("file_dot", "input{sep}.")):
    add_reject(f"must_name_file.{_id}", f"the path {_arg!r} does not name a file", (_arg,), with_files, message=MUST_NAME,
               listing=("input", "sub"))


def symlink_to_valid(ctx):
    register(ctx)
    ctx.write("real", OTHER.private)
    os.symlink("real", ctx.path("link"))


def dangling_symlink(ctx):
    register(ctx)
    os.symlink("nowhere", ctx.path("link"))


def fifo(ctx):
    register(ctx)
    os.mkfifo(ctx.path("pipe"), 0o600)


def unreadable(ctx):
    if os.geteuid() == 0:
        raise SkipCase("running as root: permission bits do not apply")
    register(ctx)
    ctx.write("secret-input", OTHER.private, mode=0o000)


add_reject("symlink_to_valid_identity", "a symlink is rejected even when it points to a valid identity (lstat)", ("link",),
           symlink_to_valid, message=NOT_REGULAR, platforms=NON_WINDOWS, listing=("link", "real"))
add_reject("dangling_symlink", "a dangling symlink is rejected as not a regular file", ("link",), dangling_symlink,
           message=NOT_REGULAR, platforms=NON_WINDOWS, listing=("link",))
add_reject("fifo", "a FIFO is rejected without blocking", ("pipe",), fifo, message=NOT_REGULAR, platforms=NON_WINDOWS,
          timeout=10, listing=("pipe",))
add_reject("no_read_permission", "a file without read permission is rejected by open", ("secret-input",), unreadable,
           prefix="openat secret-input: ", platforms=NON_WINDOWS, listing=("secret-input",))


# --- Inputs stay as they were -------------------------------------------------------------------------------

def mode_check(name, want_mode):
    def check(ctx, obs):
        mode = stat.S_IMODE(os.lstat(ctx.path(name)).st_mode)
        return only_file(name)(ctx, obs) + ([] if mode == want_mode else [f"permission bits changed to {mode:04o}"])
    return check


for _mode_bits in (0o600, 0o400, 0o644, 0o666, 0o755):
    # Setup mode is observed before and after by the harness (type, size, mode, content); the hook re-checks the mode.
    add_success(f"inspect.unchanged.mode_{_mode_bits:04o}", f"an input with mode {_mode_bits:04o} keeps its mode and bytes",
                fixtures.vectors()[1], False, "input", True, platforms=NON_WINDOWS,
                extra_check=mode_check("input", _mode_bits),
                setup=lambda ctx, bits=_mode_bits: os.chmod(ctx.path("input"), bits))
