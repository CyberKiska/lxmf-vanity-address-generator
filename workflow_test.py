"""Parse workflows and execute gating logic with disposable command stubs."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


def workflow_bash():
    if os.name == "nt":
        # Use Git for Windows' native MSYS Bash. An unqualified bash.exe can
        # launch the System32 WSL shim with a different filesystem and PATH.
        git = shutil.which("git")
        if git:
            result = subprocess.run([git, "--exec-path"], check=True, capture_output=True, text=True)
            for parent in Path(result.stdout.strip()).parents:
                bash = parent / "usr/bin/bash.exe"
                if bash.is_file():
                    return str(bash)
        return None
    return shutil.which("bash")


BASH = workflow_bash()


@unittest.skipUnless(shutil.which("ruby") and BASH, "workflow parsing requires Ruby's standard YAML library and Bash")
class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {}
        for name in ("build-binaries", "reference-compat", "reference-notify", "rust"):
            path = Path(__file__).parent / ".github/workflows" / (name + ".yml")
            result = subprocess.run(["ruby", "-rjson", "-ryaml", "-e",
                                     "puts JSON.generate(YAML.load_file(ARGV[0]))", str(path)],
                                    check=True, capture_output=True, text=True)
            cls.workflows[name] = json.loads(result.stdout)

    def test_privileged_jobs_do_not_execute_project_or_reference_code(self):
        jobs = self.workflows["build-binaries"]["jobs"]
        self.assertEqual(jobs["build"]["permissions"], {"contents": "read"})
        self.assertTrue({"smoke", "compatibility"} <= set(jobs["attest"]["needs"]))
        self.assertIn("attest", jobs["release"]["needs"])
        for name in ("attest", "release"):
            job = jobs[name]
            self.assertIn("github.event_name == 'push'", job["if"])
            for step in job["steps"]:
                self.assertNotIn("checkout", step.get("uses", ""))
                self.assertNotIn("go run", step.get("run", ""))
                self.assertNotIn("python", step.get("run", ""))
        issue = self.workflows["reference-notify"]["jobs"]["notify-failure"]
        self.assertEqual(issue["permissions"], {"issues": "write", "actions": "read"})
        self.assertIn("github.event.workflow_run.event == 'schedule'", issue["if"])
        self.assertIn("head_repository.full_name == github.repository", issue["if"])

    def test_every_release_binary_is_built_uploaded_executed_and_attested(self):
        jobs = self.workflows["build-binaries"]["jobs"]
        makefile = Path(__file__).with_name("Makefile").read_text()
        targets = next(line.split(":=")[1].split() for line in makefile.splitlines()
                       if line.startswith("TARGETS :="))
        native = jobs["smoke"]["strategy"]["matrix"]["include"]
        self.assertCountEqual(targets, [f"{m['goos']}/{m['goarch']}" for m in native])
        self.assertEqual([m["goarch"] for m in native if m["goos"] == "darwin"], ["arm64"])
        files = ["lxmf-vanity-" + t.replace("/", "-") + (".exe" if t.startswith("windows/") else "")
                 for t in targets]
        uploads = [s["with"]["binary"] for s in jobs["build"]["steps"]
                   if s.get("uses") == "./.github/actions/upload-binary"]
        self.assertCountEqual(files, uploads)
        attestation = next(s for s in jobs["attest"]["steps"] if s.get("uses", "").startswith("actions/attest@"))
        self.assertCountEqual(["artifacts/" + name for name in files],
                              attestation["with"]["subject-path"].split())

    def test_rust_workflow_is_read_only_pinned_and_runs_on_every_native_runner(self):
        workflow = self.workflows["rust"]
        job = workflow["jobs"]["check"]
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        # Ruby's YAML reads the key `on` as the boolean true.
        self.assertEqual(set(workflow.get("on") or workflow["true"]), {"push", "pull_request"})
        native = {m["runner"] for m in self.workflows["build-binaries"]["jobs"]["smoke"]["strategy"]["matrix"]["include"]}
        self.assertEqual(set(job["strategy"]["matrix"]["runner"]), native)
        for step in job["steps"]:
            self.assertRegex(step.get("uses", "x/y@" + "0" * 40), r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
            self.assertNotIn("cache", step.get("uses", "") + str(step.get("with", {})))
        self.assertNotIn("secrets.", (Path(__file__).parent / ".github/workflows/rust.yml").read_text())
        channel = tomllib.loads((Path(__file__).parent / "rust/rust-toolchain.toml").read_text())["toolchain"]["channel"]
        self.assertEqual(workflow["env"]["RUSTUP_TOOLCHAIN"], channel)
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        for required in ("rustup toolchain install", "cargo fmt --all --check",
                         "cargo clippy --workspace --all-targets --locked -- -D warnings",
                         "cargo test --workspace --locked", "scripts/check_rust_deps.py",
                         "-m unittest check_rust_deps_test"):
            self.assertIn(required, commands)

    def test_conformance_steps_run_the_verified_artifact_isolated_on_every_target(self):
        workflow = self.workflows["build-binaries"]
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        job = workflow["jobs"]["smoke"]
        steps = job["steps"]
        verify = next(i for i, s in enumerate(steps) if s.get("id") == "verify")
        self.assertIn("scripts/smoke_artifact.py", steps[verify]["run"])
        conformance = [(i, s) for i, s in enumerate(steps) if "conformance/run.py" in s.get("run", "")]
        self.assertEqual(len(conformance), 2)
        binary = ("artifact/lxmf-vanity-${{ matrix.goos }}-${{ matrix.goarch }}"
                  "${{ matrix.goos == 'windows' && '.exe' || '' }}")
        for index, step in conformance:
            self.assertGreater(index, verify)
            self.assertEqual(step["shell"], "bash")
            self.assertEqual(step["env"]["BINARY"], binary)
            # No matrix condition: the step runs on every entry, and only after a verified artifact.
            self.assertNotIn("matrix", step["if"])
            self.assertIn("steps.verify.outcome == 'success'", step["if"])
            self.assertIn('python -I conformance/run.py --binary "$BINARY"', step["run"])
            self.assertNotIn("go ", step["run"].replace("go-", ""))
        full, slow = (step["run"] for _, step in conformance)
        self.assertIn("--exclude-tag slow", full)
        self.assertIn("--report", full)
        self.assertNotIn("--tag slow", full)
        self.assertIn("--tag slow", slow)
        self.assertEqual(slow.count("for attempt in 1 2; do"), 1)
        upload = steps[conformance[-1][0] + 1]
        self.assertTrue(upload["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["path"], "conformance-*.json")
        # The release and attestation jobs download "lxmf-vanity-*" bundles; reports must not match.
        self.assertTrue(upload["with"]["name"].startswith("conformance-"))
        self.assertNotIn("conformance-", workflow["jobs"]["release"]["steps"][0]["with"]["pattern"])

    def test_pinned_reference_job_is_read_only_secretless_and_skips_forks(self):
        workflow = self.workflows["build-binaries"]
        job = workflow["jobs"]["pinned-reference"]
        smoke = workflow["jobs"]["smoke"]
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", job["if"])
        self.assertNotIn("pinned-reference", workflow["jobs"]["attest"]["needs"])
        self.assertEqual([(m["goos"], m["goarch"], m["runner"]) for m in job["strategy"]["matrix"]["include"]],
                         [(m["goos"], m["goarch"], m["runner"]) for m in smoke["strategy"]["matrix"]["include"]])
        text = json.dumps([job, smoke])
        for forbidden in ("secrets.", "token", "actions/cache", "go run", "pull_request_target"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(job["env"]["RELEASE_URL"], "https://github.com/${{ github.repository }}/releases/download")
        for name in ("pinned-reference", "smoke", "build"):
            for step in workflow["jobs"][name]["steps"]:
                uses = step.get("uses", "./")
                self.assertTrue(uses.startswith("./") or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", uses), uses)
        steps = {s.get("id"): s for s in job["steps"] if "id" in s}
        full, slow = (s for s in job["steps"] if "conformance/run.py" in s.get("run", ""))
        for step in (full, slow):
            self.assertIn('python -I conformance/run.py --binary "$binary"', step["run"])
        self.assertEqual(full["if"], "steps.record.outputs.present == 'true'")
        self.assertIn("steps.download.outcome == 'success'", slow["if"])
        self.assertEqual(steps["download"]["if"], "steps.record.outputs.present == 'true'")

    def pinned_step(self, name):
        return next(s for s in self.workflows["build-binaries"]["jobs"]["pinned-reference"]["steps"]
                    if s.get("name", "").startswith(name))

    def run_pinned(self, step, root, **env):
        shim = Path(root, "bin")
        shim.mkdir(exist_ok=True)
        (shim / "python").write_text(f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "$@"\n', newline="\n")
        (shim / "python").chmod(0o700)
        env = dict(os.environ, **env)
        return subprocess.run([BASH, "-c", 'export PATH="$PWD/bin:$PATH"\n' + step["run"]], cwd=root, env=env,
                              capture_output=True, text=True, timeout=60)

    def test_pinned_reference_is_skipped_with_a_notice_until_the_record_exists(self):
        step = self.pinned_step("Check for the pinned")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(GITHUB_OUTPUT=str(root / "out"), GITHUB_STEP_SUMMARY=str(root / "summary"))
            (root / "conformance").mkdir()
            result = self.run_pinned(step, root, **env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("::notice title=Pinned v1 reference skipped::", result.stdout)
            self.assertEqual((root / "out").read_text(), "present=false\n")
            self.assertIn("skipped", (root / "summary").read_text())
            (root / "conformance/reference.json").write_text("{}")
            (root / "out").unlink()
            result = self.run_pinned(step, root, **env)
            self.assertEqual((root / "out").read_text(), "present=true\n")
            self.assertNotIn("::notice", result.stdout)

    def test_pinned_download_accepts_only_the_recorded_bytes_and_names(self):
        step = self.pinned_step("Download the pinned")
        data = b"pinned release bytes"
        good = hashlib.sha256(data).hexdigest()
        cases = (  # (target os, tag, file, sha256, passes)
            ("linux", "v1.0.0", "lxmf-vanity-linux-amd64", good, True),
            ("windows", "v1.0.0", "lxmf-vanity-windows-amd64.exe", good, True),
            ("linux", "v1.0.0", "lxmf-vanity-linux-amd64", hashlib.sha256(b"other").hexdigest(), False),
            ("linux", "v1.0.0", "lxmf-vanity-linux-amd64", good.upper(), False),
            ("linux", "v1.0.0", "lxmf-vanity-linux-arm64", good, False),
            ("linux", "v1.0.0", "../lxmf-vanity-linux-amd64", good, False),
            ("linux", "v1.0.0/../x", "lxmf-vanity-linux-amd64", good, False),
            ("windows", "v1.0.0", "lxmf-vanity-windows-amd64", good, False),
        )
        for target_os, tag, name, digest, passes in cases:
            with self.subTest(target_os=target_os, tag=tag, name=name, passes=passes), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "conformance").mkdir()
                (root / "releases/v1.0.0").mkdir(parents=True)
                suffix = ".exe" if target_os == "windows" else ""
                (root / f"releases/v1.0.0/lxmf-vanity-{target_os}-amd64{suffix}").write_bytes(data)
                record = {"tag": tag, "artifacts": {f"{target_os}-amd64": {"file": name, "sha256": digest}}}
                (root / "conformance/reference.json").write_text(json.dumps(record))
                result = self.run_pinned(step, root, TARGET_OS=target_os, TARGET_ARCH="amd64",
                                         RELEASE_URL=(root / "releases").as_uri())
                saved = root / "pinned" / f"lxmf-vanity-{target_os}-amd64{suffix}"
                self.assertEqual(result.returncode == 0, passes, result.stderr)
                self.assertEqual(saved.is_file(), passes)
                if passes:
                    self.assertEqual(saved.read_bytes(), data)

    def test_core_and_interop_gates_fail_closed(self):
        steps = self.workflows["reference-compat"]["jobs"]["reference"]["steps"]
        script = next(s["run"] for s in steps if s.get("name", "").startswith("Mandatory core"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".venv/bin").mkdir(parents=True)
            reference = root / ".venv/bin/python"
            reference.write_text("#!/bin/sh\ncase \"$*\" in *'--checks core'*) exit \"$CORE_CODE\";; "
                                 "*) exit \"$INTEROP_CODE\";; esac\n", newline="\n")
            reference.chmod(0o700)
            for core, interop, passes in ((0, 0, True), (0, 3, True), (1, 0, False),
                                          (2, 0, False), (3, 0, False), (0, 1, False),
                                          (0, 2, False), (0, 4, False)):
                env = dict(os.environ, CORE_CODE=str(core), INTEROP_CODE=str(interop),
                           GITHUB_STEP_SUMMARY="summary")
                result = subprocess.run([BASH, "-c", 'export PATH="$PWD:$PATH"\n' + script], cwd=root, env=env,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, passes, (core, interop, result.stderr))

    def test_issue_failure_notification_is_deduplicated(self):
        job = self.workflows["reference-notify"]["jobs"]["notify-failure"]
        script = job["steps"][0]["run"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text("#!/bin/sh\ncase \"$1 $2\" in\n"
                          "'issue list') if [ -f created ]; then printf '1\\n'; else printf '0\\n'; fi;;\n"
                          "'run download') exit 1;;\n'label create') exit 0;;\n'issue create') printf 'created\\n' >> created;;\n"
                          "*) exit 91;;\nesac\n", newline="\n")
            gh.chmod(0o700)
            env = dict(os.environ, RUN_LINK="https://example.invalid/run", REFERENCE_RUN_ID="123")
            for _ in range(2):
                subprocess.run([BASH, "-c", 'export PATH="$PWD:$PATH"\n' + script], cwd=root, env=env, check=True,
                               capture_output=True, timeout=10)
            self.assertEqual((root / "created").read_text(), "created\n")

    def test_all_inline_bash_is_syntactically_valid(self):
        for workflow in self.workflows.values():
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    if "run" in step and (step.get("shell") == "bash" or job.get("runs-on") == "ubuntu-latest"):
                        subprocess.run([BASH, "-n"], input=step["run"].encode("utf-8"),
                                       check=True, capture_output=True)
