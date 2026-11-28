"""Save-path cases: what a user can observe when the tool saves, refuses to save, or falls back.

Every case uses disposable identities that exist only inside the harness's per-run temporary directory.
Saves use one- and two-character patterns (16**n expected attempts). Groups:
happy path and sidecar, private exports, refusals before the search, Unix directory policy, fallback,
long-pattern hint, concurrency. Paths are written as {tmp} and {sep}; the Windows variants need the
acknowledgement flags of REFERENCE_FACTS 10. The helpers marked private are local to the case modules and
may move to fixtures.py later.
"""

import base64
import os
import re

from conformance import harness
from conformance.cases.search_modes import (
    HINT, KEYS_FAILED, KEYS_FOUND, found_check, public_problems, search_lines)
from conformance.harness import Case, Expectation, SkipCase, current_platform

WINDOWS_HOST = current_platform() == "windows"
FLAGS = ("--allow-weak-output-protection",) if WINDOWS_HOST else ()
NON_WINDOWS = frozenset({"linux", "darwin"})
UNIX = NON_WINDOWS
WINDOWS = frozenset({"windows"})
CASE_INSENSITIVE_HOSTS = frozenset({"darwin", "windows"})  # where Go compares names with EqualFold
OUT = "{tmp}{sep}out{sep}id"
FB = "{tmp}{sep}fb{sep}id2"
BASE = ("--prefix", "0", "--workers", "1", "--json")
SAVED_FILES = {"out/id": (64, 0o600), "out/id.txt": (None, 0o600)}
SYNC_LIMIT = "directory sync unsupported on this filesystem; power-loss durability is not verified"
WINDOWS_NOTICES = {
    SYNC_LIMIT,
    "Weak output protection explicitly accepted: access-control verification is unavailable; inherited Windows ACLs must already be restricted",
    "Weak output protection explicitly accepted: private-file ACL verification is unavailable",
}
WEAK_DIR = "directory is group/other writable without sticky-entry protection"
WEAK_REFUSED = f"output protection refused: {WEAK_DIR}; use --allow-weak-output-protection only for an intentionally trusted location"
WEAK_ACCEPTED = f"Weak output protection explicitly accepted: {WEAK_DIR}"
STICKY = "sticky shared directory: its owner can alter entries; use a private directory"
GIT = "Output directory is a Git checkout; prefer a private directory outside source control."
EXISTS = "{path} already exists; refusing to overwrite"
OVERLAP = "primary and fallback identity/sidecar paths overlap"
NOT_A_FILE = "output path must name a file"
WINDOWS_ACL = ("refusing to write a private identity with an unverified inherited Windows ACL; secure the output directory, "
               "then explicitly pass --allow-inherited-windows-acl")
QUIET = {"verified_files": [], "unverified_files": [], "deviations": []}
CASES = []


# --- private helpers (candidates for fixtures.py) -------------------------------------------------------

def add(cid, description, args, expect, **kw):
    kw.setdefault("random_identity", True)
    kw.setdefault("attempts_nondeterministic", True)
    CASES.append(Case(id=f"save_path.{cid}", description=description, args=tuple(args), expect=expect, **kw))


def not_root(ctx):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SkipCase("running as root: directory policy cases need an unprivileged user")


def make(*, out_mode=0o700, fb=False, files=(), dirs=(), links=(), unprivileged=False):
    """A setup that creates out/ (and fb/), then the given files, directories and dangling symlinks."""
    def setup(ctx):
        if unprivileged:
            not_root(ctx)
        ctx.mkdir("out")
        if fb:
            ctx.mkdir("fb")
        for name in files:
            ctx.write(name, b"existing")
        for name in dirs:
            ctx.mkdir(name)
        for name in links:
            try:
                os.symlink(ctx.tmp / "nowhere", ctx.path(name))
            except (OSError, NotImplementedError):
                raise SkipCase("cannot create symlinks here") from None
        if out_mode != 0o700 and os.name != "nt":
            os.chmod(ctx.path("out"), out_mode)
    return setup


def stderr_expect(lines, notices=()):
    """Exact stderr on Unix. On Windows any 'Notice:' lines may precede the search lines."""
    wanted = [f"Notice: {n}" for n in notices] + list(lines)
    if not WINDOWS_HOST:
        return {"stderr_lines": tuple(wanted)}
    return {"stderr_regex": r"\A(Notice: [^\n]*\n)*" + "".join(re.escape(line) + r"\n" for line in lines) + r"\Z"}


def notice_json(notices):
    """JSON notices are exact on Unix and a subset of the known set on Windows (checked by the case)."""
    return {} if WINDOWS_HOST else {"notices": list(notices)}


def notices_ok(fields, notices):
    got = fields["notices"]
    if WINDOWS_HOST:
        return [] if set(got) <= WINDOWS_NOTICES else [f"unexpected notices {got}"]
    return [] if got == list(notices) else [f"notices {got}, expected {list(notices)}"]


def sidecar_text(fields, name, exports=None):
    """The exact sidecar of REFERENCE_FACTS 9."""
    x, e, a, h = fields["x25519_public"], fields["ed25519_public"], fields["address"], fields["identity_hash"]
    lines = ["LXMF Vanity Address Identity", "============================", "", f"Address (LXMF): {a}",
             f"Identity Hash:  {h}", f"Full Specifier: <lxmf.delivery.{h}:{a}>", "", "Public Key (X25519 + Ed25519):",
             f"  X25519 Public:  {x}", f"  Ed25519 Public: {e}", f"  Combined:       {x}{e}", "",
             f'Private identity file: "{name}"']
    if exports is None:
        lines.append("This metadata file contains public information only.")
    else:
        lines += ["", "WARNING: Reversible private identity exports follow. Protect this file like the identity file.",
                  "Reticulum URL-safe Base64 private identity:", f"  {exports[0]}",
                  "Reticulum Base32 private identity:", f"  {exports[1]}"]
    return "\n".join(lines + ["", "Verify with:", "  rnid -i <identity_file> -H lxmf.delivery"]) + "\n"


def saved_check(*, rel="out", name="id", exports=False, notices=()):
    """Everything a verified save promises: files, cross-inspection by the peer, sidecar, exports, notices."""
    def check(ctx, obs):
        fields, fails = obs.json, []
        fails += public_problems(fields) + notices_ok(fields, notices)
        path = ctx.tmp / rel / name
        data = path.read_bytes()
        if len(data) != 64:
            return fails + [f"identity file has {len(data)} bytes, expected 64"]
        if fields["verified_files"] != [str(path)]:
            fails.append("verified_files is not exactly the absolute path of the identity file")
        if data[0] & 7 or data[31] & 0x80 or not data[31] & 0x40:
            fails.append("the stored X25519 private key is not clamped")
        seen = harness.inspect_with(ctx.peer, path)
        fails += [f"the peer binary reads {k} differently" for k, v in seen.items() if fields[k] != v]
        try:
            side = (ctx.tmp / rel / (name + ".txt")).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return fails + ["the sidecar is missing or not UTF-8"]
        if str(ctx.tmp) in side:
            fails.append("the sidecar contains the absolute directory")
        if exports:
            b64, b32 = base64.urlsafe_b64encode(data).decode(), base64.b32encode(data).decode()
            fails += [] if (len(b64), len(b32)) == (88, 104) else ["export lengths are not 88 and 104"]
            lines = side.split("\n")
            try:
                got = (lines[lines.index("Reticulum URL-safe Base64 private identity:") + 1],
                       lines[lines.index("Reticulum Base32 private identity:") + 1])
                if base64.urlsafe_b64decode(got[0][2:]) != data or base64.b32decode(got[1][2:]) != data:
                    fails.append("the exports do not decode to the identity file")
            except (ValueError, IndexError):
                fails.append("the export lines are missing or malformed")
            if data.hex() in side.lower():
                fails.append("the sidecar contains the raw hex of the private key")
        if side != sidecar_text(fields, name, (b64, b32) if exports else None):
            fails.append("the sidecar differs from the expected format")
        return fails
    return check


def saved(cid, description, args, *, rel="out", name="id", pattern=("0", ""), exports=False, notices=(),
          setup=None, files=None, stderr_notices=None, workers=1, generator="segmented", **kw):
    """A case that must end in a verified save at <tmp>/<rel>/<name>."""
    pre, post = pattern
    path = "{tmp}{sep}" + rel.replace("/", "{sep}") + "{sep}" + name
    found = found_check(pre, post)
    saves = saved_check(rel=rel, name=name, exports=exports, notices=notices)
    expect = Expectation(
        exit_code=0, files=files if files is not None else SAVED_FILES, json_keys=KEYS_FOUND,
        json={"status": "saved", **QUIET, **notice_json(notices), "verified_files": [path], "generator": generator},
        check=lambda ctx, obs: found(ctx, obs) + saves(ctx, obs),
        **stderr_expect(search_lines(pre, post, workers, generator), notices if stderr_notices is None else stderr_notices))
    add(cid, description, args, expect, setup=setup or make(), **kw)


def refused(cid, description, args, error, *, setup=None, prefix_only=False, **kw):
    """A refusal before the search: exit 1, attempts 0, nothing created, existing files unchanged."""
    expect = dict(exit_code=1, files={}, json_keys=KEYS_FAILED,
                  json={"status": "failed", **QUIET, "notices": [], "attempts": 0, "generator": "segmented"})
    if prefix_only:  # the message after the prefix is operating-system text
        error = error.replace("{sep}", os.sep)  # only {tmp} is normalized in output; the separator is real
        expect["check"] = lambda ctx, obs: ([] if obs.json["error"].startswith(error) else ["error text differs"])
        expect["stderr_regex"] = r"\AError: " + re.escape(error)
    else:
        expect["json"] = {**expect["json"], "error": error}
        expect["stderr_lines"] = (f"Error: {error}",)
    kw.update(random_identity=False, attempts_nondeterministic=False)  # attempts is exactly 0
    add(cid, description, args, Expectation(**expect), setup=setup or make(), **kw)


# --- 4. Happy path ----------------------------------------------------------------------------------------

saved("happy.default", "--prefix 0 saves id (64 bytes) and id.txt, both 0600, with no leftovers or notices",
      (*BASE, "--out", OUT, *FLAGS), name="id")
saved("happy.windows_inherited_acl", "Windows: --allow-inherited-windows-acl saves with only the allowed notices",
      (*BASE, "--out", OUT, "--allow-inherited-windows-acl"), platforms=WINDOWS)
saved("happy.postfix_and_prefix", "a prefix and postfix save, and the address matches both",
      ("--prefix", "a", "--postfix", "B", "--workers", "2", "--json", "--out", OUT, *FLAGS), pattern=("a", "B"), workers=2)
saved("happy.independent_generator", "the independent generator saves the same way",
      (*BASE, "--generator", "independent", "--out", OUT, *FLAGS), generator="independent")
saved("happy.other_name", "an output name other than 'id' is used for both files and in the sidecar's quoted line",
      (*BASE, "--out", "{tmp}{sep}out{sep}my key", *FLAGS), name="my key",
      files={"out/my key": (64, 0o600), "out/my key.txt": (None, 0o600)})
add("happy.text_mode", "text mode prints the found address, attempts and the verified path",
    (*BASE[:-1], "--out", OUT), Expectation(
        exit_code=0, files=SAVED_FILES, stderr_lines=search_lines("0", "", 1),
        stdout_regex=r"\AFound matching address: 0[0-9a-f]{31}\n  Total attempts: [1-9][0-9]*\n  Saved and verified: "
                     + re.escape("{tmp}" + os.sep + "out" + os.sep + "id") + r"\n\Z"),
    setup=make(), platforms=NON_WINDOWS, compare=frozenset({"exit", "files", "stderr_markers"}))
saved("happy.exports", "--include-private-exports writes the WARNING block with Base64 (88) and Base32 (104) that decode to id",
      (*BASE, "--include-private-exports", "--out", OUT, *FLAGS), exports=True, allow_sidecar_exports=True)
saved("happy.exports_independent", "private exports with the independent generator",
      (*BASE, "--include-private-exports", "--generator", "independent", "--out", OUT, *FLAGS),
      exports=True, generator="independent", allow_sidecar_exports=True)

# --- 6. Refusals before the search ------------------------------------------------------------------------

for name, setup in (("id", make(files=("out/id",))), ("id_txt", make(files=("out/id.txt",))),
                    ("both", make(files=("out/id", "out/id.txt"))),
                    ("dangling_symlink_id", make(links=("out/id",))), ("dangling_symlink_id_txt", make(links=("out/id.txt",)))):
    target = "id.txt" if name in ("id_txt", "dangling_symlink_id_txt") else "id"
    refused(f"refuse.existing_{name}", f"an existing {name.replace('_', ' ')} is refused before the search and left unchanged",
            (*BASE, "--out", OUT, *FLAGS), EXISTS.format(path="{tmp}{sep}out{sep}" + target), setup=setup)
refused("refuse.missing_directory", "a missing output directory is refused",
        (*BASE, "--out", "{tmp}{sep}nodir{sep}id", *FLAGS),
        "open output directory: open {tmp}{sep}nodir" + ("" if WINDOWS_HOST else ": no such file or directory"),
        prefix_only=WINDOWS_HOST)
for cid, out in (("dot", "{tmp}{sep}out{sep}."), ("trailing_separator", "{tmp}{sep}out{sep}"), ("dotdot", "{tmp}{sep}out{sep}.."),
                 ("empty", ""), ("current_directory", ".")):
    refused(f"refuse.name_{cid}", f"--out {out!r} does not name a file", (*BASE, "--out", out, *FLAGS), NOT_A_FILE)
for cid, args, setup in (
        ("same_name", ("--out", OUT, "--fallback-out", OUT), None),
        ("fallback_is_primary_sidecar", ("--out", OUT, "--fallback-out", OUT + ".txt"), None),
        ("primary_is_fallback_sidecar", ("--out", OUT + ".txt", "--fallback-out", OUT), None),
        ("same_directory_spelled_differently", ("--out", OUT, "--fallback-out", "{tmp}{sep}out{sep}..{sep}out{sep}id"), None)):
    refused(f"refuse.overlap_{cid}", f"primary and fallback overlap ({cid.replace('_', ' ')}): refused, nothing created",
            (*BASE, *args, *FLAGS), OVERLAP, setup=setup)
for cid, fallback in (("case_only", "ID"), ("case_only_sidecar", "ID.TXT")):
    refused(f"refuse.overlap_{cid}", "names that differ only in case overlap where Go compares with EqualFold (macOS, Windows)",
            (*BASE, "--out", OUT, "--fallback-out", "{tmp}{sep}out{sep}" + fallback, *FLAGS), OVERLAP, platforms=CASE_INSENSITIVE_HOSTS)
saved("overlap.case_differs_linux", "on Linux names that differ only in case do not overlap: the primary is saved",
      (*BASE, "--out", OUT, "--fallback-out", "{tmp}{sep}out{sep}ID", *FLAGS), platforms=frozenset({"linux"}))
refused("refuse.windows_without_acknowledgement", "Windows refuses to save without an acknowledgement flag",
        (*BASE, "--out", OUT), WINDOWS_ACL, platforms=WINDOWS)
refused("refuse.fallback_existing_file", "an existing file at the fallback name is refused before the search",
        (*BASE, "--out", OUT, "--fallback-out", FB, *FLAGS), EXISTS.format(path="{tmp}{sep}fb{sep}id2"),
        setup=make(fb=True, files=("fb/id2",)))
refused("refuse.fallback_missing_directory", "a missing fallback directory is refused",
        (*BASE, "--out", OUT, "--fallback-out", "{tmp}{sep}nofb{sep}id2", *FLAGS),
        "open output directory: open {tmp}{sep}nofb" + ("" if WINDOWS_HOST else ": no such file or directory"),
        prefix_only=WINDOWS_HOST)

# --- 7. Unix directory policy (skipped as root) -----------------------------------------------------------

for mode in (0o770, 0o707, 0o777, 0o722):
    refused(f"policy.refused_{mode:04o}", f"a {mode:04o} output directory without the sticky bit is refused",
            (*BASE, "--out", OUT), WEAK_REFUSED, setup=make(out_mode=mode, unprivileged=True), platforms=UNIX)
    saved(f"policy.weak_accepted_{mode:04o}", f"--allow-weak-output-protection saves in a {mode:04o} directory, with a notice",
          (*BASE, "--allow-weak-output-protection", "--out", OUT), notices=(WEAK_ACCEPTED,),
          setup=make(out_mode=mode, unprivileged=True), platforms=UNIX)
saved("policy.sticky_1777", "a sticky 1777 directory is accepted with the sticky-directory notice",
      (*BASE, "--out", OUT), notices=(STICKY,), setup=make(out_mode=0o1777, unprivileged=True), platforms=UNIX)
saved("policy.sticky_1777_with_weak_flag", "the weak flag changes nothing for a sticky directory: only the sticky notice",
      (*BASE, "--allow-weak-output-protection", "--out", OUT), notices=(STICKY,),
      setup=make(out_mode=0o1777, unprivileged=True), platforms=UNIX)
for mode in (0o755, 0o750, 0o700):
    saved(f"policy.accepted_{mode:04o}", f"a {mode:04o} directory has no group or other write permission: saved with no notice",
          (*BASE, "--out", OUT), setup=make(out_mode=mode, unprivileged=True), platforms=UNIX)
saved("policy.git_directory", "an entry named .git (a directory) gives the Git notice and still saves",
      (*BASE, "--out", OUT), notices=(GIT,), setup=make(dirs=("out/.git",)), platforms=UNIX)
saved("policy.git_file", "an entry named .git (a file, as in a worktree) gives the Git notice too",
      (*BASE, "--out", OUT), notices=(GIT,), setup=make(files=("out/.git",)), platforms=UNIX)
saved("policy.git_and_weak", "two notices keep their order: the directory policy first, then Git",
      (*BASE, "--allow-weak-output-protection", "--out", OUT), notices=(WEAK_ACCEPTED, GIT),
      setup=make(out_mode=0o770, dirs=("out/.git",), unprivileged=True), platforms=UNIX)

def weak_fallback(ctx):
    not_root(ctx)
    ctx.mkdir("out")
    ctx.mkdir("fb", 0o770)


refused("policy.fallback_directory_refused", "a group-writable fallback directory is refused although the primary is healthy",
        (*BASE, "--out", OUT, "--fallback-out", FB), WEAK_REFUSED, setup=weak_fallback, platforms=UNIX)

# --- 8. Fallback ------------------------------------------------------------------------------------------

saved("fallback.healthy_primary", "with a healthy primary the fallback directory ends up empty, probes removed",
      (*BASE, "--out", OUT, "--fallback-out", FB, *FLAGS), setup=make(fb=True))
saved("fallback.same_directory", "a fallback in the primary's directory with another name leaves only the primary's files",
      (*BASE, "--out", OUT, "--fallback-out", "{tmp}{sep}out{sep}id2", *FLAGS))
saved("fallback.with_retry_timeout", "--save-retry-timeout does not change a healthy save",
      (*BASE, "--out", OUT, "--fallback-out", FB, "--save-retry-timeout", "30s", *FLAGS), setup=make(fb=True))
saved("fallback.retry_timeout_alone", "--save-retry-timeout without a fallback is accepted in saving mode",
      (*BASE, "--out", OUT, "--save-retry-timeout", "30s", *FLAGS))
saved("fallback.git_notice_in_both", "the same notice from both targets prints twice on stderr and once in the JSON",
      (*BASE, "--out", OUT, "--fallback-out", FB), notices=(GIT,), stderr_notices=(GIT, GIT),
      setup=make(fb=True, dirs=("out/.git", "fb/.git")), platforms=UNIX)
for cid, args in (("dry_run_fallback", ("--dry-run", "--prefix", "0", "--fallback-out", FB)),
                  ("dry_run_retry_timeout", ("--dry-run", "--prefix", "0", "--save-retry-timeout", "1s")),
                  ("benchmark_fallback", ("--benchmark", "50ms", "--fallback-out", FB)),
                  ("benchmark_retry_timeout", ("--benchmark", "50ms", "--save-retry-timeout", "1s"))):
    add(f"fallback.{cid}", f"{' '.join(args[:1])} with recovery options is a usage error (exit 2)", args,
        Expectation(exit_code=2, stdout=b"", files={}, stderr_lines=("Error: save recovery options require saving mode",)),
        setup=make(fb=True), compare=frozenset({"exit", "stdout", "files", "stderr_markers"}))

# --- 9. Long-pattern hint ---------------------------------------------------------------------------------


def hint_case(cid, description, args, *, hint, pattern, dry_run=False):
    pre, post = pattern
    expect = Expectation(
        exit_code=4, files={}, json_keys=KEYS_FAILED,
        json={"status": "limited", **QUIET, "attempts": 1, "generator": "segmented", "error": "search attempt limit reached"},
        check=lambda ctx, obs: notices_ok(obs.json, ()),
        **stderr_expect(search_lines(pre, post, 1, dry_run=dry_run, hint=hint)))
    add(cid, description, ("--workers", "1", "--max-attempts", "1", "--json", *args), expect, setup=make(fb=True),
        random_identity=False, attempts_nondeterministic=False)  # attempts is exactly 1


hint_case("hint.nine_characters", "9 characters in saving mode without a fallback print the hint, and the cap ends the run at once",
          ("--prefix", "123456789", "--out", OUT, *FLAGS), hint=True, pattern=("123456789", ""))
hint_case("hint.prefix_and_postfix", "the hint counts prefix and postfix together (5 + 4)",
          ("--prefix", "12345", "--postfix", "6789", "--out", OUT, *FLAGS), hint=True, pattern=("12345", "6789"))
hint_case("hint.long_postfix", "a long postfix alone prints the hint", ("--postfix", "0123456789abcdef", "--out", OUT, *FLAGS),
          hint=True, pattern=("", "0123456789abcdef"))
hint_case("hint.absent_at_eight", "8 characters are not 'more than 8': no hint",
          ("--prefix", "12345678", "--out", OUT, *FLAGS), hint=False, pattern=("12345678", ""))
hint_case("hint.absent_with_fallback", "with a fallback configured the hint is not printed",
          ("--prefix", "123456789", "--out", OUT, "--fallback-out", FB, *FLAGS), hint=False, pattern=("123456789", ""))
hint_case("hint.absent_in_dry_run", "dry-run writes nothing, so it never prints the hint",
          ("--prefix", "123456789", "--dry-run"), hint=False, pattern=("123456789", ""), dry_run=True)

# --- 10. Concurrency smoke --------------------------------------------------------------------------------

saved("concurrency.eight_workers", "8 workers racing on a 2-character prefix save exactly one identity",
      ("--workers", "8", "--prefix", "00", "--json", "--out", OUT, *FLAGS), pattern=("00", ""), workers=8)
saved("concurrency.eight_workers_independent", "8 workers on the independent generator also save exactly one identity",
      ("--workers", "8", "--prefix", "00", "--json", "--generator", "independent", "--out", OUT, *FLAGS),
      pattern=("00", ""), workers=8, generator="independent")
saved("concurrency.eight_workers_three_characters", "8 workers racing on a 3-character prefix save exactly one identity",
      ("--workers", "8", "--prefix", "000", "--json", "--out", OUT, *FLAGS), pattern=("000", ""), workers=8)
