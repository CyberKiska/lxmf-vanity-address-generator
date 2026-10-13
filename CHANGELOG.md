# Changelog

All notable user-visible changes are recorded here.

## Unreleased

### Added

- Startup known-answer checks for standard and segmented derivation.
- Preflighted fallback output, save retries, a retry deadline, and fresh two-interrupt discard confirmation.
- Search attempt/time limits, public JSON results, public-only identity inspection, and reproducible `--version` output.
- Progress probability and remaining-time estimates; plain pipes receive infrequent status lines.
- Canonical Go module path, installation and security-reporting guidance.
- Current stable RNS/LXMF compatibility workflows with both providers, actual LXMF delivery construction, recorded wheel provenance, and scheduled failure notification.
- Six native artifact smoke jobs, cross-host reproducibility checking, isolated attestations and owner-tag release publication, all using the same artifact bytes.
- `make lint` and `make gate` with a shared build-target list.

### Changed

- The default segmented generator draws both inputs independently at segment start, refreshes the signing seed for each discarded candidate, and replaces the X25519 half after 65,536 candidates. `--generator independent` redraws both halves for every candidate.
- CLI parsing is independent of execution; help succeeds and invalid arguments exit with status 2 before searching.
- Progress and notices use stderr; stdout contains only the final public result.
- Public sidecars disclose only a quoted basename. The verifier explicitly reports absent/skipped metadata and gives remediation for legacy unlabelled private exports.
- CI selects its toolchain from `go.mod`, checks all six target vets and module hygiene, and runs Python tests on Linux/macOS/Windows.
- Verification dependencies updated to cryptography 50.0.2 and pycparser 3.11 with wheel hashes; artifact uploads use the pinned 7.0.2 action.

### Fixed

- Completed matching candidates survive another worker's returned error and search cancellation; worker errors remain diagnostics.
- Blocked progress and closed pipes cannot delay saving a winner. Failed final delivery returns status 3 when an identity was saved.
- Save gates rederive fields and recheck the pattern; exact bounded read-back, retained complete temporaries, hard-link corruption detection and bounded recovery state prevent false saved reports.
- Preflight exercises writing, sync, publication and read-back. Moved output directories remain anchored and are reported as saved deviations.
- Explicit recovery discard returns cancellation status 130 even when unverified files and warnings remain.
- Directory-sync limitations preserve other errors; artifact smoke accepts only the explicitly reported Windows durability and ACL limitations.
- Windows path validation rejects trailing separators in either syntax.
- A complete save exits 0 on Windows: unavailable directory flushing is reported as a notice (new `notices` JSON field and `Note:` lines), not a deviation.
- A sidecar collision no longer reports a deleted temporary as a verified recovery file.
- Hard-link failures reported as `errors.ErrUnsupported` (including on Windows) use the exclusive-create fallback.
- Recovery explains when the output directory is no longer at its path and retries cannot be redirected.
- `--allow-inherited-windows-acl` outside Windows is a usage error (status 2).
- Final text and JSON results retain output-protection notices, including notices discovered after preflight.

### Security

- Unsafe Unix directory ownership/write modes are refused. Private-file ownership/mode are checked before writing secrets and during read-back. An explicit portable override reports accepted weaknesses; Windows retains acknowledgement of unverified ACLs.
- Secret aggregates use pointers and owned private buffers are cleared before final output, subject to Go/runtime and operating-system limits.
- Best-effort Unix core-dump suppression and Linux dumpability reduction occur before handling private input.
- Release toolchain moved to Go 1.27.2, and the minimum to Go 1.26.9, after the pinned scanner found reachable Windows `os.Root` advisory GO-2026-6604.
- Reference dependencies are hash-pinned; upstream code runs with read-only permissions and without privileged-job executable reuse.
- The verifier reports upstream exception types without printing exception values that could contain private identity material.
