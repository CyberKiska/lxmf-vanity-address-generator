"""Unit tests of the conformance harness, using a fake command-line program written in Python."""

import base64
import contextlib
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

from conformance import harness, run
from conformance.cases import load_cases
from conformance.harness import Case, Expectation

POSIX = os.name != "nt"
# PUBLIC TEST DATA: a fixed pseudo-key derived from a label, never a real identity.
SECRET = hashlib.sha512(b"conformance harness unit test").digest()
OTHER_SECRET = hashlib.sha512(b"another unit test key").digest()

# The fake binary. FAKE_SCRIPT (or FAKE_SCRIPT_<ROLE>) is a JSON list of steps, so one case
# can make the reference and the candidate behave differently.
FAKE = r'''
import json, os, sys, time
role = sys.argv[1]
# Raw bytes: the harness compares them, so Windows must not turn \n into \r\n.
sys.stdout.reconfigure(newline="")
sys.stderr.reconfigure(newline="")
args = sys.argv[2:]
if "--inspect" in args:
    path = args[args.index("--inspect") + 1]
    if not os.path.exists(path):
        sys.stderr.write("Error: no such file\n")
        sys.exit(1)
    sys.stdout.write(json.dumps({"status": "inspected", "address": "a" * 32, "identity_hash": "b" * 32,
        "x25519_public": "c" * 64, "ed25519_public": "d" * 64, "public_key": "c" * 64 + "d" * 64,
        "attempts": 0, "elapsed_seconds": 0, "generator": "segmented", "version": "fake"}) + "\n")
    sys.exit(0)
script = json.loads(os.environ.get("FAKE_SCRIPT_" + role.upper(), os.environ.get("FAKE_SCRIPT", "[]")))
code = 0
for step in script:
    op = step[0]
    if op == "out":
        sys.stdout.buffer.write(step[1].encode("utf-8", "surrogateescape")); sys.stdout.buffer.flush()
    elif op == "err":
        sys.stderr.buffer.write(step[1].encode("utf-8", "surrogateescape")); sys.stderr.buffer.flush()
    elif op == "env":
        sys.stdout.write(json.dumps(dict(os.environ)) + "\n")
    elif op == "args":
        sys.stdout.write(json.dumps({"args": args}) + "\n")
    elif op == "cwd":
        sys.stdout.write(os.getcwd() + "\n")
    elif op == "cwd_err":
        sys.stderr.write(os.getcwd() + "\n")
    elif op == "cwd_json":
        sys.stdout.write(json.dumps({"status": "x", "path": os.getcwd()}) + "\n")
    elif op == "stdin":
        sys.stdout.write("stdin:%d\n" % len(sys.stdin.buffer.read()))
    elif op == "write":
        with open(step[1], "wb") as f:
            f.write(bytes.fromhex(step[2]))
        if step[3] is not None and os.name != "nt":
            os.chmod(step[1], step[3])
    elif op == "append":
        with open(step[1], "ab") as f:
            f.write(step[2].encode())
    elif op == "mkdir":
        os.mkdir(step[1])
        if step[2] is not None and os.name != "nt":
            os.chmod(step[1], step[2])
    elif op == "pid":
        with open(os.environ["FAKE_PIDFILE"], "a") as f:
            f.write("%d\n" % os.getpid())
    elif op == "child":
        import subprocess
        child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
        with open(os.environ["FAKE_PIDFILE"], "a") as f:
            f.write("%d\n" % child.pid)
    elif op == "sleep":
        time.sleep(step[1])
    elif op == "trap":  # count the named signals; "wait_for" reports each one on stderr
        import signal
        received = []
        for name in step[1:]:
            signal.signal(getattr(signal, "SIG" + name), lambda num, frame: received.append(signal.Signals(num).name[3:]))
    elif op == "wait_for":
        seen = 0
        deadline = time.time() + 60
        while seen < step[1] and time.time() < deadline:
            time.sleep(0.01)
            while seen < len(received):
                sys.stderr.write("sig:%s\n" % received[seen]); sys.stderr.flush(); seen += 1
    elif op == "flood":  # a lot of output on both streams, to prove the pipes are drained
        for stream in (sys.stdout, sys.stderr):
            for _ in range(step[1] // 100):
                stream.write("x" * 99 + "\n")
            stream.flush()
    elif op == "out_pipe":  # write to stdout; a broken pipe is exit code 7
        try:
            time.sleep(step[2]); sys.stdout.buffer.write(step[1].encode()); sys.stdout.buffer.flush()
        except BrokenPipeError:
            os._exit(7)
    elif op == "stderr_full":  # is the stderr pipe full right now?
        os.set_blocking(2, False)
        try:
            os.write(2, b"x"); sys.stdout.write("room\n")
        except BlockingIOError:
            sys.stdout.write("full\n")
        os.set_blocking(2, True)
        sys.stdout.flush()
    elif op == "flaky":  # fails the first time it runs, passes later
        if not os.path.exists(step[1]):
            open(step[1], "w").close()
            code = 1
    elif op == "exit":
        code = step[1]
sys.exit(code)
'''


def alive(pid):
    """True while the process runs. A zombie is dead: in a container, PID 1 may never reap orphans."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return True


def b32(data):
    return base64.b32encode(data).decode()


def encodings(data):
    """The encodings a leak could use for `data`, as text."""
    return {"hex": data.hex(), "HEX": data.hex().upper(), "base64": base64.b64encode(data).decode(),
            "urlsafe": base64.urlsafe_b64encode(data).decode(), "base32": b32(data), "base32 lower": b32(data).lower()}


def jstr(obj):
    return json.dumps(obj) + "\n"


class FakeBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix="lxmf-conf-test-")
        cls.script = str(Path(cls.work, "fake.py"))
        Path(cls.script).write_text(FAKE, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def target(self, role="candidate"):
        return harness.Target((sys.executable, "-I", self.script, role), role)

    def case(self, script=(), reference_script=None, candidate_script=None, **kwargs):
        env = {"FAKE_SCRIPT": json.dumps(list(script))}
        if reference_script is not None:
            env["FAKE_SCRIPT_REFERENCE"] = json.dumps(reference_script)
        if candidate_script is not None:
            env["FAKE_SCRIPT_CANDIDATE"] = json.dumps(candidate_script)
        kwargs.setdefault("expect", Expectation(exit_code=None))
        return Case(id="unit.case", description="unit test case", env={**env, **kwargs.pop("env", {})}, **kwargs)

    def single(self, case, **kwargs):
        return harness.run_case(case, self.target(), **kwargs)

    def differential(self, case, **kwargs):
        return harness.run_case(case, self.target("candidate"), self.target("reference"), **kwargs)

    def failures(self, result):
        return "\n".join(result.failures)


class PassFailTests(FakeBinaryTest):
    def test_matching_run_passes_and_mismatches_fail(self):
        script = [["out", "hello\n"], ["err", "warn\n"], ["exit", 3]]
        good = Expectation(exit_code=3, stdout="hello\n", stderr_lines=("warn",), files={})
        self.assertEqual(self.single(self.case(script, expect=good)).status, "PASS")
        for name, change in (("exit", {"exit_code": 0}), ("stdout", {"stdout": "bye\n"}),
                             ("stderr", {"stderr_lines": ("other",)}), ("files", {"files": {"x": (None, None)}})):
            with self.subTest(name):
                result = self.single(self.case(script, expect=Expectation(**{**good.__dict__, **change})))
                self.assertEqual(result.status, "FAIL", result.failures)

    def test_expectation_variants(self):
        script = [["out", jstr({"status": "ok", "n": 1})], ["err", "first\nsecond\n"]]
        exp = Expectation(exit_code=0, json={"status": "ok", "n": 1}, json_keys=("status", "n"),
                          stdout_regex=r'"status": "ok"', stderr_contains=("second",), stderr_excludes=("third",),
                          stderr_regex=r"^first$")
        self.assertEqual(self.single(self.case(script, expect=exp)).status, "PASS")
        for change in ({"json": {"n": 2}}, {"json_keys": ("n", "status")}, {"stdout_regex": "zzz"},
                       {"stderr_contains": ("third",)}, {"stderr_excludes": ("first",)}, {"stderr_regex": "^third$"}):
            with self.subTest(change=change):
                bad = Expectation(**{**exp.__dict__, **change})
                self.assertEqual(self.single(self.case(script, expect=bad)).status, "FAIL")

    def test_custom_check_failures_and_exceptions_fail_the_case(self):
        script = [["out", "x"]]
        ok = Expectation(exit_code=None, check=lambda ctx, obs: [])
        self.assertEqual(self.single(self.case(script, expect=ok)).status, "PASS")
        bad = Expectation(exit_code=None, check=lambda ctx, obs: ["custom failure"])
        self.assertIn("custom failure", self.failures(self.single(self.case(script, expect=bad))))
        boom = Expectation(exit_code=None, check=lambda ctx, obs: 1 / 0)
        self.assertIn("ZeroDivisionError", self.failures(self.single(self.case(script, expect=boom))))

    def test_crash_marker_and_signal_death_are_failures(self):
        result = self.single(self.case([["err", "panic: boom\n"]]))
        self.assertIn("crash marker", self.failures(result))
        result = self.single(self.case([["err", "thread 'main' panicked at src/x.rs:1:1:\n"]]))
        self.assertIn("crash marker", self.failures(result))

    def test_unrunnable_binary_fails_the_case_without_raising(self):
        result = harness.run_case(self.case(), harness.Target((str(Path(self.work, "missing")),), "missing"))
        self.assertEqual(result.status, "FAIL")
        self.assertIn("cannot execute", self.failures(result))

    def test_setup_error_fails_only_that_case(self):
        def boom(ctx):
            raise ValueError("setup exploded")
        result = self.single(self.case(setup=boom))
        self.assertEqual(result.status, "FAIL")
        self.assertIn("ValueError", self.failures(result))

    def test_skips(self):
        other = frozenset({"windows"} if POSIX else {"linux"})
        self.assertEqual(self.single(self.case(platforms=other)).status, "SKIP")
        self.assertEqual(self.single(self.case(platforms=frozenset({harness.current_platform()}))).status, "PASS")

        def skip(ctx):
            raise harness.SkipCase("running as root")
        result = self.single(self.case(setup=skip))
        self.assertEqual((result.status, result.notes), ("SKIP", ["running as root"]))

    def test_case_validation(self):
        for kwargs in ({"id": "nodots"}, {"id": "Bad.Id"}, {"compare": frozenset({"nope"})},
                       {"platforms": frozenset({"beos"})}, {"deviation_expect": Expectation()}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Case(**{"id": "a.b", "description": "d", **kwargs})


class TimeoutTests(FakeBinaryTest):
    def test_timeout_kills_the_process_and_reports_it(self):
        started = time.monotonic()
        result = self.single(self.case([["sleep", 60]], timeout=0.5))
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("(timeout)", result.failures[0])
        self.assertIn("(timeout)", run.describe(result).splitlines()[0])

    @unittest.skipUnless(POSIX, "process groups are Unix only")
    def test_timeout_kills_the_process_and_its_children(self):
        pidfile = Path(self.work, "pids")
        pidfile.unlink(missing_ok=True)
        case = self.case([["pid"], ["child"], ["sleep", 60]], timeout=1.0, env={"FAKE_PIDFILE": str(pidfile)})
        self.assertEqual(self.single(case).status, "FAIL")
        pids = [int(line) for line in pidfile.read_text().split()]
        self.assertEqual(len(pids), 2)
        deadline = time.monotonic() + 10
        for pid in pids:
            while alive(pid):
                self.assertLess(time.monotonic(), deadline, f"process {pid} survived the timeout")
                time.sleep(0.05)

    def test_default_timeout_applies_when_the_case_sets_none(self):
        result = self.single(self.case([["sleep", 60]]), default_timeout=0.5)
        self.assertIn("(timeout)", self.failures(result))


class IsolationTests(FakeBinaryTest):
    def test_environment_is_scrubbed_to_path_plus_the_case_env(self):
        leaked = {"GODEBUG": "fips140=only", "GOMAXPROCS": "3", "HOME": "/home/x", "LXMF_VANITY_TEST": "1",
                  "CANARY": "1"}
        with mock.patch.dict(os.environ, leaked):
            result = self.single(self.case([["env"]], env={"EXTRA": "{sep}"}))
        seen = result.candidate.json
        self.assertEqual(result.status, "PASS", result.failures)
        names = {name.upper() for name in seen}
        self.assertFalse(names & {"GODEBUG", "GOMAXPROCS", "HOME", "LXMF_VANITY_TEST", "CANARY"}, names)
        self.assertEqual(seen["EXTRA"], os.sep)
        self.assertEqual(seen["PATH"], os.environ["PATH"])
        # The interpreter itself may add a locale or platform variable; nothing else may appear.
        allowed = {"PATH", "EXTRA", "FAKE_SCRIPT", "LC_CTYPE", "__CF_USER_TEXT_ENCODING", "SYSTEMROOT", "TEMP", "TMP",
                   "SYSTEMDRIVE", "PYTHONUTF8", "PYTHONIOENCODING"}
        self.assertLessEqual(names, allowed, names - allowed)

    def test_case_env_can_set_and_remove_variables(self):
        result = self.single(self.case([["env"]], env={"GODEBUG": "fips140=on", "PATH": None}))
        seen = {k.upper(): v for k, v in result.candidate.json.items()}
        self.assertEqual(seen["GODEBUG"], "fips140=on")
        self.assertNotIn("PATH", seen)

    def test_stdin_is_empty_by_default_and_can_be_given(self):
        self.assertEqual(self.single(self.case([["stdin"]], expect=Expectation(stdout="stdin:0\n"))).status, "PASS")
        given = self.case([["stdin"]], stdin=b"abc", expect=Expectation(stdout="stdin:3\n"))
        self.assertEqual(self.single(given).status, "PASS")

    def test_each_run_has_a_private_fresh_working_directory(self):
        seen = []

        def remember(ctx, obs):
            seen.append(ctx.tmp)
            self.assertTrue(ctx.tmp.is_dir())
            if POSIX:
                self.assertEqual(os.stat(ctx.tmp).st_mode & 0o777, 0o700)
            self.assertEqual(list(ctx.tmp.iterdir()), [])
            return []
        case = self.case([["cwd"]], expect=Expectation(stdout="{tmp}\n", check=remember))
        self.assertEqual(self.single(case).status, "PASS")
        self.assertEqual(self.single(case).status, "PASS")
        self.assertNotEqual(seen[0], seen[1])
        self.assertFalse(seen[0].exists() or seen[1].exists(), "temporary directories are removed")
        self.assertFalse(harness._inside(seen[0], harness.REPO_ROOT))

    def test_placeholders_in_args_and_normalization_of_tmp(self):
        def setup(ctx):
            ctx.add_fixture("data", ctx.write("data.bin", b"x"))
        case = self.case([["args"]], args=("{tmp}", "{fixture:data}", "a{sep}b", "{unknown}"), setup=setup,
                         expect=Expectation(json={"args": ["{tmp}", "{tmp}{sep}data.bin", "a{sep}b", "{unknown}"]}))
        result = self.single(case)
        self.assertEqual(result.status, "PASS", result.failures)

    def test_unknown_fixture_fails_the_case(self):
        result = self.single(self.case(args=("{fixture:none}",)))
        self.assertIn("unknown fixture", self.failures(result))

    def test_tmp_prefix_is_normalized_in_every_stream_and_compares_equal_across_runs(self):
        script = [["cwd"], ["err", "Warning: at "], ["cwd_err"]]
        case = self.case(script, compare=frozenset({"stdout_exact", "stderr", "stderr_markers"}))
        result = self.differential(case)
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual(result.candidate.stdout, b"{tmp}\n")
        self.assertEqual(result.candidate.stderr_lines, ["Warning: at {tmp}"])
        self.assertNotEqual(result.candidate.stdout, os.fsencode(os.getcwd()))
        json_result = self.differential(self.case([["cwd_json"]], compare=frozenset({"json"})))
        self.assertEqual(json_result.candidate.json["path"], "{tmp}")
        self.assertEqual(json_result.status, "PASS")


class ObservationTests(FakeBinaryTest):
    def test_created_files_are_reported_with_size_and_mode_and_setup_files_excluded(self):
        def setup(ctx):
            ctx.write("existing.txt", b"setup")
            ctx.mkdir("pre")
        script = [["write", "new.bin", "00" * 10, 0o600], ["mkdir", "subdir", 0o700],
                  ["write", "pre/inner", "01", 0o640]]
        result = self.single(self.case(script, setup=setup))
        files = {f["path"]: f for f in result.candidate.files}
        self.assertEqual(sorted(files), ["new.bin", "pre/inner", "subdir"])
        self.assertEqual((files["new.bin"]["type"], files["new.bin"]["size"]), ("file", 10))
        self.assertEqual(files["subdir"]["type"], "dir")
        self.assertEqual(files["pre/inner"]["size"], 1)
        if POSIX:
            self.assertEqual([files[p]["mode"] for p in sorted(files)], [0o600, 0o640, 0o700])
        else:
            self.assertIsNone(files["new.bin"]["mode"])  # not applicable on Windows
        mode = (10, 0o600) if POSIX else (10, None)
        good = Expectation(files={"new.bin": mode, "subdir": (None, None), "pre/inner": (1, None)})
        self.assertEqual(self.single(self.case(script, setup=setup, expect=good)).status, "PASS")
        for name, files in (("size", {"new.bin": (11, None), "subdir": (None, None), "pre/inner": (1, None)}),
                            ("missing", {"new.bin": mode, "pre/inner": (1, None)}),
                            ("extra", {"new.bin": mode, "subdir": (None, None), "pre/inner": (1, None), "z": (None, None)})):
            with self.subTest(name):
                bad = self.single(self.case(script, setup=setup, expect=Expectation(files=files)))
                self.assertEqual(bad.status, "FAIL")
        if POSIX:
            wrong = Expectation(files={"new.bin": (10, 0o644), "subdir": (None, None), "pre/inner": (1, None)})
            self.assertIn("mode 0600", self.failures(self.single(self.case(script, setup=setup, expect=wrong))))

    def test_nothing_created_is_checked_with_an_empty_mapping(self):
        self.assertEqual(self.single(self.case(expect=Expectation(files={}))).status, "PASS")
        result = self.single(self.case([["write", "x", "00", None]], expect=Expectation(files={})))
        self.assertIn("'x' was not expected", self.failures(result))

    def test_modified_and_removed_setup_files_are_detected(self):
        def setup(ctx):
            ctx.write("input", b"abc")
            ctx.mkdir("d")
        result = self.single(self.case([["append", "input", "z"]], setup=setup))
        self.assertIn("input file changed: modified input", self.failures(result))
        loose = self.single(self.case([["append", "input", "z"]], setup=setup, expect=Expectation(exit_code=None, unchanged=False)))
        self.assertEqual(loose.status, "PASS")
        self.assertEqual(self.single(self.case(setup=setup)).status, "PASS")

    def test_fifos_and_symlinks_are_recorded_without_being_opened(self):
        if not POSIX:
            self.skipTest("FIFOs and symlinks need POSIX")

        def setup(ctx):
            os.mkfifo(ctx.tmp / "pipe")
            os.symlink("nowhere", ctx.tmp / "dangling")
        result = self.single(self.case([["write", "made", "00", None]], setup=setup))
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual([f["path"] for f in result.candidate.files], ["made"])

    def test_json_is_parsed_only_for_one_object_and_a_newline(self):
        cases = {'{"a":1}\n': True, '{"a":1}': False, '{"a":1}\n\n': False, '[1]\n': False, 'x\n': False,
                 '{"a":NaN}\n': False, '{"a":1}\n{"b":2}\n': False}
        for text, parsed in cases.items():
            with self.subTest(text=text):
                self.assertEqual(harness.parse_result(text.encode()) is not None, parsed)

    def test_binary_output_is_not_decoded_strictly(self):
        result = self.single(self.case([["out", "a\udcffb\n"], ["err", "\udcfe\n"]]))
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual(result.candidate.stdout, b"a\xffb\n")
        report = harness.build_report([result], "single", "fake", None)
        json.dumps(report)  # lone surrogates must still serialize

    def test_paths_with_spaces_work(self):
        spaced = Path(self.work, "dir with space")
        spaced.mkdir()
        script = spaced / "fake.py"
        script.write_text(FAKE, encoding="utf-8")
        target = harness.Target((sys.executable, "-I", str(script), "candidate"), "spaced")
        case = self.case([["write", "a file", "00", None]], args=("{tmp}{sep}x y",),
                         expect=Expectation(files={"a file": (1, None)}))
        self.assertEqual(harness.run_case(case, target).status, "PASS")

    def test_target_from_path_checks_the_file(self):
        with self.assertRaises(harness.HarnessError):
            harness.Target.from_path(Path(self.work, "nope"))
        if POSIX:
            with self.assertRaises(harness.HarnessError):
                harness.Target.from_path(self.script)  # exists but is not executable
            self.assertEqual(harness.Target.from_path(sys.executable).label, Path(sys.executable).name)


class JsonTests(FakeBinaryTest):
    def test_elapsed_and_version_are_masked_and_validated(self):
        base = {"status": "ok", "elapsed_seconds": 12.5, "version": "abc"}
        script = [["out", jstr(base)]]
        result = self.single(self.case(script, expect=Expectation(json={"status": "ok"})))
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.candidate.json["elapsed_seconds"], harness.MASK)
        self.assertEqual(result.candidate.json["version"], harness.MASK)  # masks are all equal
        for bad in ({"elapsed_seconds": -1}, {"elapsed_seconds": "1"}, {"version": ""}, {"version": 3}):
            with self.subTest(bad=bad):
                result = self.single(self.case([["out", jstr({**base, **bad})]]))
                self.assertEqual(result.status, "FAIL")

    def test_identity_fields_are_checked_and_masked_only_for_random_identities(self):
        good = {"status": "dry-run", "address": "a" * 32, "identity_hash": "b" * 32, "x25519_public": "c" * 64,
                "ed25519_public": "d" * 64, "public_key": "c" * 64 + "d" * 64}
        script = [["out", jstr(good)]]
        plain = self.single(self.case(script))
        self.assertEqual(plain.candidate.json["address"], "a" * 32)
        masked = self.single(self.case(script, random_identity=True))
        self.assertEqual(masked.candidate.json["address"], harness.MASK)
        self.assertEqual(masked.candidate.json["public_key"], harness.MASK)
        for field, value in (("address", "A" * 32), ("address", "a" * 31), ("x25519_public", "g" * 64),
                             ("public_key", "e" * 128), ("ed25519_public", "d" * 63)):
            with self.subTest(field=field, value=value[:5]):
                result = self.single(self.case([["out", jstr({**good, field: value})]], random_identity=True))
                self.assertEqual(result.status, "FAIL", result.failures)

    def test_attempts_are_masked_only_when_nondeterministic(self):
        script = [["out", jstr({"status": "x", "attempts": 17})]]
        self.assertEqual(self.single(self.case(script)).candidate.json["attempts"], harness.Num("17"))
        masked = self.single(self.case(script, attempts_nondeterministic=True))
        self.assertEqual(masked.candidate.json["attempts"], harness.MASK)
        # Two runs with different attempts differ unless the case says they are nondeterministic.
        ref, cand = [["out", jstr({"status": "x", "attempts": 3})]], [["out", jstr({"status": "x", "attempts": 4})]]
        strict = self.differential(self.case(reference_script=ref, candidate_script=cand, compare=frozenset({"json"})))
        self.assertIn("attempts", self.failures(strict))
        loose = self.differential(self.case(reference_script=ref, candidate_script=cand, compare=frozenset({"json"}),
                                            attempts_nondeterministic=True))
        self.assertEqual(loose.status, "PASS")

    def test_key_order_mismatch_is_detected(self):
        ref = [["out", '{"a":1,"b":2}\n']]
        cand = [["out", '{"b":2,"a":1}\n']]
        result = self.differential(self.case(reference_script=ref, candidate_script=cand,
                                             compare=frozenset({"json"})))
        self.assertEqual(result.status, "FAIL")
        self.assertIn("key order differs", self.failures(result))
        same = self.differential(self.case(reference_script=ref, candidate_script=ref, compare=frozenset({"json"})))
        self.assertEqual(same.status, "PASS")

    def test_a_different_json_version_passes_with_a_note_but_other_fields_still_fail(self):
        def program(version, **more):
            return [["out", jstr({"status": "ok", "version": version, **more})]]
        compare = frozenset({"json"})
        same = self.differential(self.case(reference_script=program("5bbe76e"),
                                           candidate_script=program("2.0.0-dev"), compare=compare))
        self.assertEqual(same.status, "PASS", same.failures)
        self.assertIn("json $.version: version differs (5bbe76e vs 2.0.0-dev); only its presence is compared",
                      "\n".join(same.notes))
        equal = self.differential(self.case(reference_script=program("1"), candidate_script=program("1"),
                                            compare=compare))
        self.assertEqual((equal.status, equal.notes), ("PASS", []))
        other = self.differential(self.case(reference_script=program("5bbe76e", note="a"),
                                            candidate_script=program("2.0.0-dev", note="b"), compare=compare))
        self.assertEqual(other.status, "FAIL")
        self.assertIn("json $.note", self.failures(other))
        self.assertNotIn("$.version", self.failures(other))
        for bad in ("", 3, None):  # presence still matters on both sides
            for side in ("reference_script", "candidate_script"):
                with self.subTest(bad=bad, side=side):
                    scripts = {"reference_script": program("5bbe76e"), "candidate_script": program("2.0.0-dev")}
                    scripts[side] = program(bad)
                    result = self.differential(self.case(compare=compare, **scripts))
                    self.assertEqual(result.status, "FAIL")

    def test_single_mode_still_masks_version_and_requires_a_non_empty_string(self):
        expect = Expectation(json={"status": "ok"})
        good = self.single(self.case([["out", jstr({"status": "ok", "version": "x"})]], expect=expect))
        self.assertEqual((good.status, good.notes), ("PASS", []))
        for bad in ("", 3):
            result = self.single(self.case([["out", jstr({"status": "ok", "version": bad})]], expect=expect))
            self.assertEqual(result.status, "FAIL")

    def test_json_stdout_bytes_are_compared_with_only_the_top_level_version_value_masked(self):
        def run(ref, cand, compare=("stdout_exact",)):
            return self.differential(self.case(reference_script=[["out", ref]], candidate_script=[["out", cand]],
                                               compare=frozenset(compare)))
        same = run('{"status":"ok","version":"5bbe76e","n":1}\n', '{"status":"ok","version":"2.0.0-dev","n":1}\n')
        self.assertEqual(same.status, "PASS", same.failures)
        escaped = run('{"version":"a\\"b\\\\","n":1}\n', '{"version":"\\u0041","n":1}\n', ("stdout_exact", "stdout"))
        self.assertEqual(escaped.status, "PASS", escaped.failures)
        # Everything else stays byte-exact: escaping, spelling, spacing, key order.
        for ref, cand in (('{"version":"a","p":"A"}\n', '{"version":"b","p":"\\u0041"}\n'),
                          ('{"version":"a","n":1}\n', '{"version":"b","n":1.0}\n'),
                          ('{"version":"a","n":1}\n', '{"version":"b", "n":1}\n'),
                          ('{"version":"a","n":1}\n', '{"n":1,"version":"b"}\n'),
                          ('{"version":"a","n":1}\n', '{"version":"a","n":1}'),
                          ('{"version":"a","n":1}\n', '{"version":1,"n":1}\n')):
            with self.subTest(ref=ref, cand=cand):
                self.assertEqual(run(ref, cand).status, "FAIL")
        other = run('{"version":"5bbe76e","p":"A"}\n', '{"version":"2.0.0-dev","p":"\\u0041"}\n')
        self.assertIn("stdout bytes differ at offset 28", self.failures(other))  # right after {"version":"<version>","p":"
        # A "version" that is not the top-level key does not count.
        for ref, cand in (('{"x":{"version":"a"}}\n', '{"x":{"version":"b"}}\n'),
                          ('{"x":"\\"version\\":\\"a\\""}\n', '{"x":"\\"version\\":\\"b\\""}\n'),
                          ('{"x":[{"version":"a"}],"y":1}\n', '{"x":[{"version":"b"}],"y":1}\n'),
                          ('{"version":"a","version":"c"}\n', '{"version":"b","version":"c"}\n'),
                          ('version "a"\n', 'version "b"\n')):
            with self.subTest(ref=ref, cand=cand):
                self.assertEqual(run(ref, cand).status, "FAIL")
        # The masked value does not hide a version nested next to a masked top-level one.
        nested = run('{"version":"a","x":{"version":"a"}}\n', '{"version":"b","x":{"version":"b"}}\n')
        self.assertEqual(nested.status, "FAIL")

    def test_single_mode_stdout_keeps_the_version_bytes(self):
        out = '{"version":"v1","n":1}\n'
        case = self.case([["out", out]], expect=Expectation(stdout=out))
        self.assertEqual(self.single(case).status, "PASS")
        wrong = self.case([["out", out]], expect=Expectation(stdout=out.replace("v1", "v2")))
        self.assertEqual(self.single(wrong).status, "FAIL")

    def test_missing_and_extra_keys_are_detected(self):
        ref, cand = [["out", '{"a":1}\n']], [["out", '{"a":1,"b":2}\n']]
        result = self.differential(self.case(reference_script=ref, candidate_script=cand, compare=frozenset({"json"})))
        self.assertIn("keys differ", self.failures(result))

    def test_zero_and_zero_point_zero_are_equal_with_a_note(self):
        ref, cand = [["out", '{"x":0,"elapsed_seconds":0}\n']], [["out", '{"x":0.0,"elapsed_seconds":0.0}\n']]
        result = self.differential(self.case(reference_script=ref, candidate_script=cand, compare=frozenset({"json"})))
        self.assertEqual(result.status, "PASS", result.failures)
        notes = "\n".join(result.notes)
        self.assertIn("$.x: number text differs (0 vs 0.0)", notes)
        self.assertIn("$.elapsed_seconds", notes)  # masked, but a change of text is still noted
        # exponent forms of the same value are equal too; different values are not
        ref, cand = [["out", '{"x":1e21}\n']], [["out", '{"x":1000000000000000000000}\n']]
        self.assertEqual(self.differential(self.case(reference_script=ref, candidate_script=cand,
                                                     compare=frozenset({"json"}))).status, "PASS")
        cand = [["out", '{"x":0.5}\n']]
        ref = [["out", '{"x":0}\n']]
        self.assertEqual(self.differential(self.case(reference_script=ref, candidate_script=cand,
                                                     compare=frozenset({"json"}))).status, "FAIL")

    def test_strings_arrays_and_types_compare_exactly(self):
        cases = {"string": ('{"s":"a"}', '{"s":"b"}'), "array element": ('{"l":[1,2]}', '{"l":[1,3]}'),
                 "array length": ('{"l":[1]}', '{"l":[1,2]}'), "type": ('{"x":true}', '{"x":1}'),
                 "null": ('{"x":null}', '{"x":0}'), "nested": ('{"o":{"k":"a"}}', '{"o":{"k":"b"}}')}
        for name, (ref, cand) in cases.items():
            with self.subTest(name):
                result = self.differential(self.case(reference_script=[["out", ref + "\n"]],
                                                     candidate_script=[["out", cand + "\n"]],
                                                     compare=frozenset({"json"})))
                self.assertEqual(result.status, "FAIL", result.failures)

    def test_only_one_side_printing_json_is_a_difference(self):
        result = self.differential(self.case(reference_script=[["out", '{"a":1}\n']], candidate_script=[["out", "text\n"]],
                                             compare=frozenset({"json"})))
        self.assertIn("only one of the runs", self.failures(result))


class DifferentialTests(FakeBinaryTest):
    def result_for(self, ref, cand, fields, **kwargs):
        return self.differential(self.case(reference_script=ref, candidate_script=cand,
                                           compare=frozenset(fields), **kwargs))

    def test_identical_runs_pass_and_every_difference_is_flagged(self):
        base = [["out", jstr({"status": "ok", "n": 1})], ["err", "Notice: a\nplain\n"],
                ["write", "f", "00" * 4, 0o600], ["write", "s.txt", "61", 0o600]]

        def changed(index, step):
            return [*base[:index], step, *base[index + 1:]]
        everything = ("exit", "stdout", "stdout_exact", "json", "files", "stderr", "stderr_markers", "sidecars")
        self.assertEqual(self.result_for(base, base, everything).status, "PASS")
        scenarios = {
            "exit": (base + [["exit", 3]], ("exit",), "exit code"),
            "stdout": (changed(0, ["out", jstr({"status": "ok", "n": 2})]), ("stdout",), "stdout line 1"),
            "stdout_exact": (changed(0, ["out", jstr({"status": "ok", "n": 2})]), ("stdout_exact",), "stdout bytes differ"),
            "json": (changed(0, ["out", jstr({"status": "ok", "n": 2})]), ("json",), "json $.n"),
            "stderr marker": (changed(1, ["err", "Notice: b\nplain\n"]), ("stderr_markers",), "stderr marker line 1"),
            "stderr all lines": (changed(1, ["err", "Notice: a\nother\n"]), ("stderr",), "stderr line 2"),
            "file size": (changed(2, ["write", "f", "00" * 5, 0o600]), ("files",), "f: size"),
            "file path": (changed(2, ["write", "g", "00" * 4, 0o600]), ("files",), "only in the"),
            "file missing": (base[:2] + base[3:], ("files",), "only in the reference"),
            "sidecar": (changed(3, ["write", "s.txt", "62", 0o600]), ("sidecars",), "contents of 's.txt' differ"),
        }
        if POSIX:
            scenarios["file mode"] = (changed(2, ["write", "f", "00" * 4, 0o644]), ("files",), "f: mode")
        for name, (cand, fields, needle) in scenarios.items():
            with self.subTest(name):
                result = self.result_for(base, cand, fields)
                self.assertEqual(result.status, "FAIL", result.failures)
                self.assertIn(needle, self.failures(result))

    def test_fields_that_are_not_compared_are_ignored(self):
        ref, cand = [["out", "a\n"], ["err", "plain 1\n"]], [["out", "b\n"], ["err", "plain 2\n"], ["exit", 9]]
        self.assertEqual(self.result_for(ref, cand, ("files",)).status, "PASS")
        self.assertEqual(self.result_for(ref, cand, ("stderr_markers",)).status, "PASS")
        self.assertEqual(self.result_for(ref, cand, ("stderr",)).status, "FAIL")

    def test_modified_inputs_differ_between_binaries(self):
        def setup(ctx):
            ctx.write("in", b"1")
        result = self.result_for([], [["append", "in", "2"]], ("files",), setup=setup)
        self.assertIn("changed input files", self.failures(result))

    def test_reference_that_misses_the_expectation_fails_the_case(self):
        exp = Expectation(exit_code=0)
        result = self.differential(self.case(reference_script=[["exit", 5]], candidate_script=[], expect=exp))
        self.assertEqual(result.status, "FAIL")
        self.assertIn("reference: exit code 5", self.failures(result))

    def test_candidate_that_misses_the_expectation_fails_even_if_equal_to_the_reference(self):
        result = self.differential(self.case([["exit", 5]], expect=Expectation(exit_code=0)))
        self.assertIn("exit code 5, expected 0", self.failures(result))

    def test_secret_and_invariant_failures_are_attributed_to_a_side(self):
        def setup(ctx):
            ctx.add_secret(SECRET)
        result = self.differential(self.case(reference_script=[], candidate_script=[["out", SECRET.hex()]], setup=setup))
        self.assertEqual(result.status, "FAIL")
        self.assertIn("candidate: secret encoding found in stdout", self.failures(result))

    def test_cross_inspection_uses_the_peer_binary(self):
        def check(ctx, obs):
            path = ctx.tmp / "id"
            path.write_bytes(bytes(64))
            mine = harness.inspect_with(ctx.target, path)
            theirs = harness.inspect_with(ctx.peer, path)
            return [] if mine == theirs else ["inspection differs"]
        result = self.differential(self.case(expect=Expectation(check=check)))
        self.assertEqual(result.status, "PASS", result.failures)

    def test_inspect_with_returns_public_fields_and_rejects_failures(self):
        path = Path(self.work, "some identity")
        path.write_bytes(bytes(64))
        fields = harness.inspect_with(self.target(), path)
        self.assertEqual(list(fields), list(harness.PUBLIC_FIELDS))
        self.assertEqual(fields["public_key"], fields["x25519_public"] + fields["ed25519_public"])
        with self.assertRaises(harness.HarnessError):
            harness.inspect_with(self.target(), Path(self.work, "missing"))


class DeviationTests(FakeBinaryTest):
    def deviating(self, **kwargs):
        return self.case(expect=Expectation(exit_code=0), deviation="DEV-unit",
                         deviation_expect=Expectation(exit_code=7), **kwargs)

    def test_single_mode_accepts_the_stated_deviation_only(self):
        self.assertEqual(self.single(self.deviating(candidate_script=[])).status, "PASS")
        result = self.single(self.deviating(candidate_script=[["exit", 7]]))
        self.assertEqual((result.status, result.deviation), ("DEVIATION", "DEV-unit"))
        self.assertEqual(run.describe(result).splitlines()[0], "DEVIATION DEV-unit unit.case")
        self.assertEqual(self.single(self.deviating(candidate_script=[["exit", 3]])).status, "FAIL")

    def test_differential_mode_accepts_a_difference_that_meets_the_deviation_expectation(self):
        result = self.differential(self.deviating(reference_script=[], candidate_script=[["exit", 7]]))
        self.assertEqual(result.status, "DEVIATION")
        wrong = self.differential(self.deviating(reference_script=[], candidate_script=[["exit", 3]]))
        self.assertEqual(wrong.status, "FAIL")
        plain = self.differential(self.case(reference_script=[], candidate_script=[["exit", 7]],
                                            expect=Expectation(exit_code=None)))
        self.assertEqual(plain.status, "FAIL")

    def test_a_deviation_never_excuses_a_leak(self):
        def setup(ctx):
            ctx.add_secret(SECRET)
        result = self.differential(self.deviating(reference_script=[], candidate_script=[["exit", 7], ["err", SECRET.hex()]],
                                                  setup=setup))
        self.assertEqual(result.status, "FAIL")


class SecretScanningTests(FakeBinaryTest):
    def register(self, ctx):
        ctx.add_secret(SECRET)

    def test_encodings_are_found_at_every_alignment(self):
        for before in range(6):
            for after in range(6):
                blob = b"x" * before + SECRET + b"y" * after
                for name, text in encodings(blob).items():
                    with self.subTest(before=before, after=after, encoding=name):
                        self.assertTrue(harness.contains_secret([SECRET], f"..{text}..".encode()))
        self.assertTrue(harness.contains_secret([SECRET], SECRET[:32].hex().encode()))  # one half of an identity
        self.assertFalse(harness.contains_secret([SECRET], b"nothing to see; " + OTHER_SECRET.hex().encode()))
        for name, text in encodings(OTHER_SECRET).items():
            self.assertFalse(harness.contains_secret([SECRET], text.encode()), name)

    def test_short_secrets_are_refused(self):
        with self.assertRaises(harness.HarnessError):
            harness.Context("candidate", None, None).add_secret(b"short")

    def test_each_encoding_is_found_in_each_stream(self):
        streams = {
            "stdout": lambda text: [["out", text + "\n"]],
            "stderr": lambda text: [["err", text + "\n"]],
            "json": lambda text: [["out", jstr({"status": "x", "note": text})]],
            "sidecar id.txt": lambda text: [["write", "id.txt", text.encode().hex(), None]],
        }
        for stream, script in streams.items():
            for name, text in encodings(SECRET).items():
                with self.subTest(stream=stream, encoding=name):
                    result = self.single(self.case(script(text), setup=self.register))
                    self.assertEqual(result.status, "FAIL")
                    self.assertIn(f"secret encoding found in {stream}", self.failures(result))
                    self.assertNotIn(text, self.failures(result))

    def test_clean_output_passes(self):
        clean = [["out", OTHER_SECRET.hex() + "\n"], ["err", "all fine\n"], ["write", "id.txt", b"public".hex(), None]]
        self.assertEqual(self.single(self.case(clean, setup=self.register)).status, "PASS")

    def test_exports_in_the_sidecar_are_allowed_only_when_the_case_says_so(self):
        exports = (encodings(SECRET)["urlsafe"] + "\n" + encodings(SECRET)["base32"] + "\n").encode().hex()
        script = [["write", "id.txt", exports, None]]
        self.assertEqual(self.single(self.case(script, setup=self.register, allow_sidecar_exports=True)).status, "PASS")
        self.assertEqual(self.single(self.case(script, setup=self.register)).status, "FAIL")
        # Allowing sidecar exports never allows them anywhere else.
        for stream in ("out", "err"):
            leak = script + [[stream, encodings(SECRET)["base32"]]]
            result = self.single(self.case(leak, setup=self.register, allow_sidecar_exports=True))
            self.assertEqual(result.status, "FAIL", stream)

    def test_identity_files_created_by_the_binary_become_secrets(self):
        key = hashlib.sha512(b"created identity").digest()
        script = [["write", "id", key.hex(), 0o600], ["out", base64.b64encode(key).decode() + "\n"]]
        result = self.single(self.case(script))
        self.assertIn("secret encoding found in stdout", self.failures(result))
        clean = self.single(self.case([["write", "id", key.hex(), 0o600]]))
        self.assertEqual(clean.status, "PASS")

    def test_mismatch_messages_never_echo_a_secret(self):
        exp = Expectation(exit_code=None, check=lambda ctx, obs: [f"mismatch near {encodings(SECRET)['urlsafe']}"])
        result = self.single(self.case(setup=self.register, expect=exp))
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(len(result.failures), 1)
        self.assertIn("withheld", result.failures[0])
        self.assertNotIn(encodings(SECRET)["urlsafe"], result.failures[0])

    def test_report_and_console_contain_no_secrets(self):
        leaking = self.case([["out", jstr({"status": "x", "k": SECRET.hex()})], ["err", encodings(SECRET)["urlsafe"]],
                             ["write", "id.txt", encodings(SECRET)["base32"].encode().hex(), None]],
                            setup=self.register)
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.json")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = run.main(["--binary", self.script_target(), "--report", str(report_path)], cases=[leaking])
            self.assertEqual(status, 1)
            report = report_path.read_text(encoding="utf-8")
        for name, text in encodings(SECRET).items():
            self.assertNotIn(text, report, name)
            self.assertNotIn(text, out.getvalue(), name)
        self.assertEqual(json.loads(report)["cases"][0]["status"], "FAIL")

    def script_target(self):
        # run.main takes a path; wrap the fake in an executable launcher where the platform allows it.
        if not POSIX:
            self.skipTest("needs an executable launcher script")
        launcher = Path(self.work, "launcher.sh")
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{self.script}" candidate "$@"\n')
        launcher.chmod(0o755)
        return str(launcher)


@unittest.skipUnless(POSIX, "the entry point tests use an executable launcher script")
class EntryPointTests(FakeBinaryTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # One launcher per role, so a single script can play both the reference and the candidate.
        for role in ("candidate", "reference"):
            path = Path(cls.work, f"{role}.sh")
            path.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{cls.script}" {role} "$@"\n')
            path.chmod(0o755)

    def main(self, *argv, cases=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                status = run.main(list(argv), cases=cases)
            except SystemExit as exc:
                status = exc.code
        return status, out.getvalue(), err.getvalue()

    def binary(self, role="candidate"):
        return str(Path(self.work, f"{role}.sh"))

    def passing(self, name="p"):
        return Case(id=f"unit.{name}", description="passes", expect=Expectation(exit_code=0, stdout="ok\n"),
                    env={"FAKE_SCRIPT": json.dumps([["out", "ok\n"]])})

    def failing(self, name="f"):
        return Case(id=f"unit.{name}", description="fails", expect=Expectation(exit_code=0),
                    env={"FAKE_SCRIPT": json.dumps([["exit", 4], ["write", "left", "00", None]])})

    def test_exit_codes_and_lines(self):
        status, out, _ = self.main("--binary", self.binary(), cases=[self.passing()])
        self.assertEqual(status, 0)
        self.assertIn("PASS unit.p", out)
        self.assertIn("summary: 1 cases, 1 passed, 0 failed, 0 skipped, 0 deviations", out)
        status, out, _ = self.main("--binary", self.binary(), cases=[self.passing(), self.failing()])
        self.assertEqual(status, 1)
        self.assertIn("FAIL unit.f", out)
        self.assertIn("exit code 4, expected 0", out)

    def test_usage_errors_exit_2(self):
        for argv in ((), ("--binary", self.binary(), "--timeout", "0"), ("--bogus",)):
            with self.subTest(argv=argv):
                self.assertEqual(self.main(*argv, cases=[self.passing()])[0], 2)
        self.assertEqual(self.main("--binary", str(Path(self.work, "nope")), cases=[self.passing()])[0], 2)
        self.assertEqual(self.main("--binary", self.binary(), "--cases", "zzz.*", cases=[self.passing()])[0], 2)
        self.assertEqual(self.main("--binary", self.binary(), "--reference", str(Path(self.work, "nope")),
                                   cases=[self.passing()])[0], 2)
        inside = str(harness.REPO_ROOT / "kept-cases")
        self.assertEqual(self.main("--binary", self.binary(), "--keep-failed", inside, cases=[self.failing()])[0], 2)
        self.assertFalse(Path(inside).exists())

    def test_a_crashing_case_does_not_abort_the_run(self):
        def boom(ctx):
            raise RuntimeError("setup exploded")
        crashing = Case(id="unit.crash", description="crashes", setup=boom)
        status, out, _ = self.main("--binary", self.binary(), cases=[crashing, self.passing("after")])
        self.assertEqual(status, 1)
        self.assertIn("FAIL unit.crash", out)
        self.assertIn("RuntimeError", out)
        self.assertIn("PASS unit.after", out)

    def test_list_and_case_globs(self):
        cases = [self.passing("a1"), self.passing("a2"), self.passing("b1")]
        status, out, _ = self.main("--list", cases=cases)
        self.assertEqual((status, out.count("\n")), (0, 3))
        status, out, _ = self.main("--binary", self.binary(), "--cases", "unit.a*", cases=cases)
        self.assertIn("summary: 2 cases", out)
        status, out, _ = self.main("--binary", self.binary(), "--cases", "unit.a1", "--cases", "unit.b1", cases=cases)
        self.assertIn("summary: 2 cases", out)

    def test_tag_and_exclude_tag_filter_and_combine_with_case_globs(self):
        def tagged(name, *tags):
            return dataclasses.replace(self.passing(name), tags=frozenset(tags))
        cases = [tagged("a", "slow"), tagged("b", "slow", "unix"), tagged("c", "unix"), tagged("d")]

        def listed(*argv):
            status, out, _ = self.main("--list", *argv, cases=cases)
            return status, [line.split("\t")[0] for line in out.splitlines()]
        self.assertEqual(listed("--exclude-tag", "slow"), (0, ["unit.c", "unit.d"]))
        self.assertEqual(listed("--tag", "slow"), (0, ["unit.a", "unit.b"]))
        self.assertEqual(listed("--tag", "slow", "--tag", "unix"), (0, ["unit.a", "unit.b", "unit.c"]))
        self.assertEqual(listed("--exclude-tag", "slow", "--exclude-tag", "unix"), (0, ["unit.d"]))
        self.assertEqual(listed("--tag", "slow", "--exclude-tag", "unix"), (0, ["unit.a"]))
        self.assertEqual(listed("--tag", "slow", "--cases", "unit.b"), (0, ["unit.b"]))
        self.assertEqual(listed("--tag", "none"), (0, []))
        # The selection also drives a real run, and an empty selection is a usage error.
        status, out, _ = self.main("--binary", self.binary(), "--exclude-tag", "slow", cases=cases)
        self.assertEqual(status, 0)
        self.assertIn("summary: 2 cases", out)
        self.assertEqual(self.main("--binary", self.binary(), "--tag", "none", cases=cases)[0], 2)

    def test_registered_slow_cases_are_selectable_and_the_rest_are_not_slow(self):
        slow = run.select(load_cases(), run.parse_args(["--list", "--tag", "slow"]))
        self.assertTrue(slow and all(c.id.startswith("signals_streams.") for c in slow))
        rest = run.select(load_cases(), run.parse_args(["--list", "--exclude-tag", "slow"]))
        self.assertEqual(len(slow) + len(rest), len(load_cases()))

    def test_differential_mode_prints_the_mode_and_compares(self):
        different = Case(id="unit.d", description="differs", expect=Expectation(exit_code=None),
                         env={"FAKE_SCRIPT_REFERENCE": json.dumps([]), "FAKE_SCRIPT_CANDIDATE": json.dumps([["exit", 2]])})
        status, out, _ = self.main("--binary", self.binary(), "--reference", self.binary("reference"),
                                   cases=[self.passing(), different])
        self.assertEqual(status, 1)
        self.assertIn("mode: differential", out)
        self.assertIn("exit code: reference 0, candidate 2", out)
        status, out, _ = self.main("--binary", self.binary(), "--reference", self.binary("reference"), cases=[self.passing()])
        self.assertEqual(status, 0)

    def test_report_lists_every_case_with_normalized_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "report.json")
            self.main("--binary", self.binary(), "--report", str(path), cases=[self.passing(), self.failing()])
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"], {"PASS": 1, "FAIL": 1, "SKIP": 0, "DEVIATION": 0})
        failed = next(c for c in report["cases"] if c["id"] == "unit.f")
        self.assertEqual((failed["status"], failed["exit_code"]), ("FAIL", 4))
        self.assertEqual(failed["observation"]["files"][0]["path"], "left")
        self.assertNotIn(str(self.work), json.dumps(report))  # no host paths from the run

    def test_keep_failed_keeps_only_failed_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            self.main("--binary", self.binary(), "--keep-failed", directory, cases=[self.passing(), self.failing()])
            self.assertTrue(Path(directory, "unit.f", "candidate", "left").is_file())
            self.assertFalse(Path(directory, "unit.p").exists())

    def test_timeout_option_is_the_default_for_cases_without_one(self):
        slow = Case(id="unit.slow", description="sleeps", expect=Expectation(exit_code=None),
                    env={"FAKE_SCRIPT": json.dumps([["sleep", 60]])})
        status, out, _ = self.main("--binary", self.binary(), "--timeout", "0.5", cases=[slow])
        self.assertEqual(status, 1)
        self.assertIn("FAIL unit.slow (timeout)", out)


@unittest.skipUnless(POSIX, "interactive runs are POSIX only")
class InteractiveTests(FakeBinaryTest):
    def interactive(self, script, interact, **kwargs):
        return self.single(self.case(script, interact=interact, **kwargs))

    def test_signals_are_sent_in_sequence_after_waiting_for_marker_lines(self):
        steps = []

        def interact(ctx, session):
            steps.append(session.wait_line("ready"))
            session.signal(signal.SIGINT)
            steps.append(session.wait_line("sig:"))
            session.signal(signal.SIGTERM)
            steps.append(session.wait_line("sig:TERM"))
            steps.append(session.wait_exit(5))

        result = self.interactive([["trap", "INT", "TERM"], ["err", "ready\n"], ["wait_for", 2], ["exit", 130]], interact,
                                  expect=Expectation(exit_code=130, stderr_lines=("ready", "sig:INT", "sig:TERM")))
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual(steps, ["ready", "sig:INT", "sig:TERM", 130])

    def test_each_wait_continues_after_the_previous_match(self):
        seen = []

        def interact(ctx, session):
            seen.append(session.wait_line("tick"))
            seen.append(session.wait_line("tick"))
            seen.append(session.stderr_lines())

        result = self.interactive([["err", "tick 1\ntick 2\n"]], interact)
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual(seen, ["tick 1", "tick 2", ["tick 1", "tick 2"]])

    def test_regex_patterns_match_anywhere_in_the_line(self):
        def interact(ctx, session):
            self.assertEqual(session.wait_line(re.compile(r"b+c")), "abbbc d")

        import re
        self.assertEqual(self.interactive([["err", "zzz\nabbbc d\n"]], interact).status, "PASS")

    def test_both_pipes_are_drained_while_waiting(self):
        sizes = []

        def interact(ctx, session):
            session.wait_line("ready")  # the flood (far beyond a pipe's capacity) comes first
            session.signal(signal.SIGINT)

        def check(ctx, obs):
            sizes.append((len(obs.stdout), len(obs.stderr)))
            return []

        result = self.interactive([["trap", "INT"], ["flood", 1_000_000], ["err", "ready\n"], ["wait_for", 1]], interact,
                                  expect=Expectation(exit_code=0, check=check))
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual(sizes, [(1_000_000, 1_000_000 + len("ready\nsig:INT\n"))])

    def test_a_line_that_never_appears_fails_the_case_and_kills_the_process(self):
        started = time.monotonic()
        result = self.interactive([["err", "other\n"], ["sleep", 60]],
                                  lambda ctx, session: session.wait_line("ready", timeout=0.5))
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(result.status, "FAIL")
        self.assertIn("(interaction) no line 'ready' within 0.5 s; last lines: ['other']", result.failures[0])
        self.assertFalse(result.candidate.timed_out)

    def test_a_process_that_exits_before_the_line_is_reported(self):
        result = self.interactive([["err", "bye\n"], ["exit", 3]], lambda ctx, session: session.wait_line("ready"))
        self.assertEqual(result.status, "FAIL")
        self.assertRegex(result.failures[0], r"\(interaction\) stderr closed \(exit code \d+\) before the line 'ready'")

    def test_a_last_line_without_newline_is_still_a_line(self):
        result = self.interactive([["err", "ready"]], lambda ctx, session: session.wait_line("ready"))
        self.assertEqual(result.status, "PASS", result.failures)

    def test_signalling_an_exited_process_and_a_hung_exit_are_failures(self):
        def late(ctx, session):
            session.wait_exit(5)
            session.signal(signal.SIGINT)

        self.assertIn("exited with code 0", self.failures(self.interactive([], late)))
        result = self.interactive([["sleep", 60]], lambda ctx, session: session.wait_exit(0.3))
        self.assertIn("did not exit within 0.3 s", self.failures(result))

    def test_a_closed_stdout_breaks_the_pipe_for_the_process(self):
        script = [["err", "ready\n"], ["out_pipe", "late\n", 0.3]]
        result = self.single(self.case(script, stdout_closed=True, expect=Expectation(exit_code=7, stdout=b"",
                                                                                       stderr_lines=("ready",))))
        self.assertEqual(result.status, "PASS", result.failures)
        self.assertEqual(self.single(self.case(script, interact=lambda ctx, session: None,
                                               expect=Expectation(exit_code=0, stdout=b"late\n"))).status, "PASS")

    def test_the_run_ends_with_the_ordinary_observation_and_secret_scan(self):
        steps = [["write", "o/id", SECRET.hex(), None], ["err", f"ready {SECRET.hex()}\n"]]
        result = self.interactive(steps, lambda ctx, session: session.wait_line("ready"),
                                  setup=lambda ctx: ctx.mkdir("o"),
                                  expect=Expectation(exit_code=0, files={"o/id": (len(SECRET) // 2 or 1, None)}))
        self.assertIn("secret encoding found in stderr", self.failures(result))
        self.assertNotIn(SECRET.hex(), self.failures(result))
        clean = self.interactive([["write", "o/id", SECRET.hex(), None], ["err", "ready\n"]],
                                 lambda ctx, session: session.wait_line("ready"), setup=lambda ctx: ctx.mkdir("o"),
                                 expect=Expectation(exit_code=0, files={"o/id": (None, None)}, stderr_lines=("ready",)))
        self.assertEqual(clean.status, "PASS", clean.failures)

    def test_the_case_timeout_still_bounds_a_run_whose_steps_all_succeed(self):
        result = self.interactive([["sleep", 60]], lambda ctx, session: None, timeout=0.5)
        self.assertIn("(timeout)", result.failures[0])
        self.assertTrue(result.candidate.timed_out)

    def test_a_crash_in_the_interaction_fails_the_case_and_leaves_no_process(self):
        pidfile = Path(self.work, "pids-interact")
        pidfile.unlink(missing_ok=True)

        def interact(ctx, session):
            session.wait_line("ready")
            raise ZeroDivisionError

        result = self.interactive([["pid"], ["child"], ["err", "ready\n"], ["sleep", 60]], interact,
                                  env={"FAKE_PIDFILE": str(pidfile)})
        self.assertIn("ZeroDivisionError", self.failures(result))
        deadline = time.monotonic() + 10
        for pid in (int(line) for line in pidfile.read_text().split()):
            while alive(pid):
                self.assertLess(time.monotonic(), deadline, f"process {pid} survived")
                time.sleep(0.05)

    def test_an_unread_stderr_pipe_is_full_from_the_start_and_its_filler_is_not_observed(self):
        result = self.single(self.case([["stderr_full"]], hold_stderr=True,
                                       expect=Expectation(exit_code=0, stdout="full\n", stderr_lines=())))
        self.assertEqual(result.status, "PASS", result.failures)
        plain = self.single(self.case([["stderr_full"]], interact=lambda ctx, session: None,
                                      expect=Expectation(exit_code=0, stdout="room\n")))
        self.assertEqual(plain.status, "PASS", plain.failures)

    def test_a_process_that_writes_to_the_unread_pipe_blocks_until_the_timeout(self):
        result = self.single(self.case([["err", "blocked\n"]], hold_stderr=True, timeout=1.0))
        self.assertIn("(timeout)", result.failures[0])

    def test_interactive_runs_work_in_differential_mode(self):
        case = self.case([["trap", "INT"], ["err", "ready\n"], ["wait_for", 1]],
                         interact=lambda ctx, session: (session.wait_line("ready"), session.signal(signal.SIGINT)),
                         compare=frozenset({"exit", "stderr"}))
        result = harness.run_case(case, self.target("candidate"), self.target("reference"))
        self.assertEqual(result.status, "PASS", result.failures)

    def test_interactive_cases_cannot_take_stdin(self):
        with self.assertRaises(ValueError):
            Case(id="a.b", description="d", interact=lambda ctx, session: None, stdin=b"x")


class RetryTests(FakeBinaryTest):
    def flaky(self, name, **kwargs):
        marker = Path(self.work, name)
        marker.unlink(missing_ok=True)
        return self.case([["flaky", str(marker)]], expect=Expectation(exit_code=0), **kwargs)

    def test_a_case_that_fails_once_passes_on_the_retry_with_a_note(self):
        result = self.single(self.flaky("retry-ok", retries=1))
        self.assertEqual((result.status, result.retried), ("PASS", True))
        self.assertTrue(result.notes[0].startswith("retry used; the first run failed: exit code 1, expected 0"))
        self.assertIn("note: retry used", run.describe(result))

    def test_without_retries_the_first_failure_stands(self):
        result = self.single(self.flaky("retry-none"))
        self.assertEqual((result.status, result.retried), ("FAIL", False))

    def test_a_case_that_fails_twice_fails_and_says_it_retried(self):
        result = self.single(self.case([["exit", 1]], expect=Expectation(exit_code=0), retries=1))
        self.assertEqual((result.status, result.retried), ("FAIL", True))
        self.assertIn("exit code 1, expected 0", result.failures[0])

    def test_a_case_that_passes_first_time_is_not_retried(self):
        result = self.single(self.case([], expect=Expectation(exit_code=0), retries=1))
        self.assertEqual((result.status, result.retried, result.notes), ("PASS", False, []))

    def test_at_most_one_retry_is_allowed(self):
        with self.assertRaises(ValueError):
            Case(id="a.b", description="d", retries=2)

    def test_the_report_records_the_retry(self):
        result = self.single(self.flaky("retry-report", retries=1))
        report = harness.build_report([result], "single", "fake", None)
        self.assertTrue(report["cases"][0]["retried"])

    def test_keep_failed_keeps_nothing_when_the_retry_passes(self):
        with tempfile.TemporaryDirectory() as keep:
            self.single(self.flaky("retry-keep", retries=1), keep_failed=keep)
            self.assertEqual(os.listdir(keep), [])


class RegistryTests(unittest.TestCase):
    def test_registered_cases_have_unique_valid_ids_and_smoke_cases_exist(self):
        cases = load_cases()
        ids = [c.id for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual([i for i in ids if i.startswith("smoke.")], ["smoke.help", "smoke.version", "smoke.version_json"])
        self.assertTrue(all(harness.CASE_ID.fullmatch(i) for i in ids))

    def test_select_cases_uses_globs(self):
        cases = load_cases()
        self.assertEqual(len(harness.select_cases(cases, [])), len(cases))
        self.assertEqual([c.id for c in harness.select_cases(cases, ["smoke.version*"])],
                         ["smoke.version", "smoke.version_json"])

    def test_harness_never_writes_into_the_repository(self):
        before = sorted(p.name for p in harness.REPO_ROOT.iterdir())
        with tempfile.TemporaryDirectory() as directory:
            ctx = harness.Context("candidate", None, None)
            try:
                self.assertFalse(harness._inside(ctx.tmp, harness.REPO_ROOT))
            finally:
                ctx.dispose()
            with mock.patch.object(harness, "REPO_ROOT", Path(tempfile.gettempdir())):
                with self.assertRaises(harness.HarnessError):
                    harness.Context("candidate", None, None)
            self.assertTrue(Path(directory).is_dir())
        self.assertEqual(sorted(p.name for p in harness.REPO_ROOT.iterdir()), before)


if __name__ == "__main__":
    unittest.main()
