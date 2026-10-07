"""Parse workflows and execute gating logic with disposable command stubs."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("ruby") and shutil.which("bash"), "workflow parsing requires Ruby's standard YAML library and bash")
class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {}
        for name in ("build-binaries", "reference-compat", "reference-notify"):
            path = Path(__file__).parent / ".github/workflows" / (name + ".yml")
            result = subprocess.run(["ruby", "-rjson", "-ryaml", "-e",
                                     "puts JSON.generate(YAML.load_file(ARGV[0]))", str(path)],
                                    check=True, capture_output=True, text=True)
            cls.workflows[name] = json.loads(result.stdout)

    def test_privileged_jobs_do_not_execute_project_or_reference_code(self):
        jobs = self.workflows["build-binaries"]["jobs"]
        self.assertEqual(jobs["build"]["permissions"], {"contents": "read"})
        for name in ("attest", "release"):
            job = jobs[name]
            self.assertIn("smoke", job["needs"])
            self.assertIn("github.event_name == 'push'", job["if"])
            for step in job["steps"]:
                self.assertNotIn("checkout", step.get("uses", ""))
                self.assertNotIn("go run", step.get("run", ""))
                self.assertNotIn("python", step.get("run", ""))
        issue = self.workflows["reference-notify"]["jobs"]["notify-failure"]
        self.assertEqual(issue["permissions"], {"issues": "write", "actions": "read"})
        self.assertIn("github.event.workflow_run.event == 'schedule'", issue["if"])
        self.assertIn("head_repository.full_name == github.repository", issue["if"])

    def test_core_and_interop_gates_fail_closed(self):
        steps = self.workflows["reference-compat"]["jobs"]["reference"]["steps"]
        script = next(s["run"] for s in steps if s.get("name", "").startswith("Mandatory core"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".venv/bin").mkdir(parents=True)
            (root / "go.mod").write_text("toolchain go1.27.1\n")
            for name, text in {
                "go": "#!/bin/sh\nprintf 'go1.27.1\\n'\n",
                "make": "#!/bin/sh\nexit 0\n",
                ".venv/bin/python": "#!/bin/sh\ncase \"$*\" in *'--checks core'*) exit \"$CORE_CODE\";; *) exit \"$INTEROP_CODE\";; esac\n",
            }.items():
                (root / name).write_text(text)
                (root / name).chmod(0o700)
            for core, interop, passes in ((0, 0, True), (0, 3, True), (1, 0, False),
                                          (2, 0, False), (3, 0, False), (0, 1, False),
                                          (0, 2, False), (0, 4, False)):
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           CORE_CODE=str(core), INTEROP_CODE=str(interop),
                           GITHUB_STEP_SUMMARY=str(root / "summary"))
                result = subprocess.run(["bash", "-c", script], cwd=root, env=env,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, passes, (core, interop))

    def test_issue_failure_notification_is_deduplicated(self):
        job = self.workflows["reference-notify"]["jobs"]["notify-failure"]
        script = job["steps"][0]["run"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text("#!/bin/sh\ncase \"$1 $2\" in\n"
                          "'issue list') if [ -f created ]; then printf '1\\n'; else printf '0\\n'; fi;;\n"
                          "'run download') exit 1;;\n'label create') exit 0;;\n'issue create') printf 'created\\n' >> created;;\n"
                          "*) exit 91;;\nesac\n")
            gh.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       RUN_LINK="https://example.invalid/run", REFERENCE_RUN_ID="123")
            for _ in range(2):
                subprocess.run(["bash", "-c", script], cwd=root, env=env, check=True,
                               capture_output=True, timeout=10)
            self.assertEqual((root / "created").read_text(), "created\n")

    def test_all_inline_bash_is_syntactically_valid(self):
        for workflow in self.workflows.values():
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    if "run" in step and (step.get("shell") == "bash" or job.get("runs-on") == "ubuntu-latest"):
                        subprocess.run(["bash", "-n"], input=step["run"], text=True,
                                       check=True, capture_output=True)
