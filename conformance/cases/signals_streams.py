"""Signals, closed or blocked streams and the save-recovery loop (Unix only).

Every case drives the running process through Case.interact: it waits for the stderr marker
`search started` (or `Save recovery:`), then sends signals or breaks a pipe. All of them are
timing based, so each is tagged `slow`, may retry once, and waits up to 60 s for a marker.

Recovery is provoked without fault injection: right after `search started` the output directory
becomes read-only (0500), so preflight has passed but publishing a new name fails. The cases skip
as root, which ignores directory permissions. The text of a recovery failure carries a random
temporary name, so these cases compare only the exit code and the created files across binaries;
each side is still checked against the full expectation.
"""

import os
import signal

from conformance import harness
from conformance.harness import Case, Expectation

WAIT = 60.0  # seconds to wait for a marker line
EXIT_WITHIN = 5.0  # seconds a cancelled process may take to exit
UNIX = frozenset({"linux", "darwin"})
SLOW = frozenset({"slow"})
SEARCH_STARTED = "search started"
RECOVERY = "Save recovery:"
ARMED = "Discard armed for 10s: press Ctrl-C again to abandon the in-memory winner."
ABANDONED = "in-memory winner explicitly abandoned; retained files are not claimed erased"
DEADLINE = "save recovery deadline reached; retained files are not claimed erased"
RECOVERY_LINE = (r"^Save recovery: .*permission denied; retry in 1s\. "
                 r"Two fresh Ctrl-C presses within 10s discard memory; retained files remain\.$")
SAVED_FILES = {"o/id": (64, 0o600), "o/id.txt": (None, 0o600)}
CASES = []


def add(cid, description, **kwargs):
    kwargs.setdefault("platforms", UNIX)
    kwargs.setdefault("tags", SLOW)
    kwargs.setdefault("retries", 1)
    kwargs.setdefault("timeout", WAIT)
    CASES.append(Case(id=f"signals_streams.{cid}", description=description, **kwargs))


def setup_output(ctx):
    ctx.mkdir("o")


def setup_recovery(ctx):
    if os.geteuid() == 0:
        raise harness.SkipCase("running as root: directory permissions do not stop it")
    setup_output(ctx)


def saved_files_verify(ctx, obs):
    """The saved identity is inspected by both binaries and shows the same public fields."""
    seen, fails = {}, []
    for label, binary in (("candidate", ctx.target), ("peer", ctx.peer)):
        try:
            seen[label] = harness.inspect_with(binary, ctx.path("o/id"))
        except harness.HarnessError as exc:
            fails.append(f"{label} cannot inspect the saved identity: {exc}")
    if len(seen) == 2 and seen["candidate"] != seen["peer"]:
        fails.append("the two binaries read different public fields from the saved identity")
    fails += [f"the saved address {fields['address']!r} does not start with the prefix 0" for fields in seen.values()
              if not fields["address"].startswith("0")]
    return fails


# --- Cancellation by signal during the search --------------------------------------------------------

def cancelled_by(signum):
    def interact(ctx, session):
        session.wait_line(SEARCH_STARTED, WAIT)
        session.signal(signum)
        session.wait_exit(EXIT_WITHIN)
    return interact


CANCELLED = Expectation(exit_code=130, files={}, json={"status": "cancelled", "error": "context canceled"})
for name in ("SIGINT", "SIGTERM", "SIGHUP"):
    add(f"cancel.{name.lower()}", f"{name} during the search exits 130 with status cancelled within 5 s and creates nothing",
        args=("--prefix", "ffffffffffff", "--dry-run", "--workers", "2", "--json"),
        interact=cancelled_by(getattr(signal, name)), expect=CANCELLED, attempts_nondeterministic=True)
add("cancel.sigint_while_saving", "SIGINT during the search of a saving run cancels it: no recovery starts and nothing is written",
    args=("--prefix", "ffffffffffff", "--workers", "2", "--json", "--out", "{tmp}/o/id"), setup=setup_output,
    interact=cancelled_by(signal.SIGINT), attempts_nondeterministic=True,
    expect=Expectation(exit_code=130, files={}, stderr_excludes=(RECOVERY, "Discard armed"),
                       json={"status": "cancelled", "error": "context canceled"}))

# --- SIGPIPE is ignored: a closed stdout is a delivery failure, never a crash -------------------------------

add("sigpipe.dry_run", "a dry run whose stdout reader is gone exits 1, not by SIGPIPE",
    args=("--prefix", "0000", "--dry-run", "--workers", "1", "--json"), stdout_closed=True,
    expect=Expectation(exit_code=1, stdout=b"", files={}))
add("sigpipe.save", "a save whose stdout reader is gone still saves, verifies and exits 3",
    args=("--prefix", "0", "--out", "{tmp}/o/id", "--json"), setup=setup_output, stdout_closed=True,
    expect=Expectation(exit_code=3, stdout=b"", files=SAVED_FILES, check=saved_files_verify))

# --- A stderr that nobody reads ----------------------------------------------------------------------------

# The pipe is full before the process starts, so every write to stderr blocks: the save must not wait for it.
add("stderr.unread_pipe_does_not_block_saving", "with stderr a full pipe nobody reads, a save still finishes with exit 0",
    args=("--prefix", "0", "--workers", "1", "--out", "{tmp}/o/id", "--json"), setup=setup_output, hold_stderr=True,
    random_identity=True, attempts_nondeterministic=True,
    expect=Expectation(exit_code=0, stderr_lines=(), files=SAVED_FILES, json={"status": "saved"},
                       check=saved_files_verify))

# --- The recovery loop ---------------------------------------------------------------------------------------

RECOVERY_ARGS = ("--prefix", "0000", "--workers", "1", "--json", "--out", "{tmp}/o/id")
RECOVERY_COMPARE = frozenset({"exit", "files"})


def in_recovery(body):
    """Run `body(session)` once the first save has failed in a read-only output directory."""
    def interact(ctx, session):
        directory = ctx.path("o")
        session.wait_line(SEARCH_STARTED, WAIT)
        os.chmod(directory, 0o500)
        try:
            session.wait_line(RECOVERY, WAIT)
            body(session)
        finally:
            os.chmod(directory, 0o700)
    return interact


def not_armed(session):
    armed = [line for line in session.stderr_lines() if line.startswith("Discard armed")]
    if armed:
        raise harness.InteractionError(f"a discard was armed: {armed[0]!r}")


def two_interrupts(session):
    session.signal(signal.SIGINT)
    session.wait_line(ARMED, WAIT)
    session.signal(signal.SIGINT)
    session.wait_exit(EXIT_WITHIN)


ABANDON = Expectation(exit_code=130, files={}, stderr_regex=RECOVERY_LINE,
                      json={"status": "cancelled", "error": ABANDONED})


def deadline(session):
    session.wait_exit(WAIT)


add("recovery.deadline", "--save-retry-timeout 2s ends a failing recovery with exit 1 and a deadline error",
    args=(*RECOVERY_ARGS, "--save-retry-timeout", "2s"), setup=setup_recovery, interact=in_recovery(deadline),
    compare=RECOVERY_COMPARE,
    expect=Expectation(exit_code=1, files={}, stderr_regex=RECOVERY_LINE, stderr_excludes=("Discard armed",),
                       json={"status": "failed", "error": DEADLINE}))
add("recovery.two_interrupts_abandon", "two SIGINTs in recovery abandon the winner: exit 130, status cancelled",
    args=RECOVERY_ARGS, setup=setup_recovery, interact=in_recovery(two_interrupts), compare=RECOVERY_COMPARE,
    expect=ABANDON)


def other_signals_do_not_arm(session):
    for signum in (signal.SIGTERM, signal.SIGHUP):
        session.signal(signum)
        session.wait_line(RECOVERY, WAIT)  # a later retry round: an armed discard would have printed before it
        not_armed(session)
    two_interrupts(session)


add("recovery.sigterm_and_sighup_do_not_arm", "SIGTERM and SIGHUP in recovery do not arm a discard; two SIGINTs still do",
    args=RECOVERY_ARGS, setup=setup_recovery, interact=in_recovery(other_signals_do_not_arm), compare=RECOVERY_COMPARE,
    expect=ABANDON)


def other_signals_do_not_confirm(session):
    session.signal(signal.SIGINT)
    session.wait_line(ARMED, WAIT)
    session.signal(signal.SIGTERM)
    session.signal(signal.SIGHUP)
    session.wait_line(RECOVERY, WAIT)  # the retry round after both signals: the winner is still held
    if session.proc.poll() is not None:
        raise harness.InteractionError("SIGTERM or SIGHUP ended the recovery after a first SIGINT")
    session.signal(signal.SIGINT)
    session.wait_exit(EXIT_WITHIN)


add("recovery.sigterm_and_sighup_do_not_confirm", "after one SIGINT, SIGTERM and SIGHUP do not confirm the discard; the next SIGINT does",
    args=RECOVERY_ARGS, setup=setup_recovery, interact=in_recovery(other_signals_do_not_confirm),
    compare=RECOVERY_COMPARE, expect=ABANDON)
