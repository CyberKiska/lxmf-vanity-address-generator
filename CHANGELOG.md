# Changelog

All notable user-visible changes are recorded here.

## Unreleased

### Added

- A changelog for security, reliability and compatibility improvements.

### Changed

- CLI configuration is parsed independently; help succeeds and invalid arguments exit with status 2 before searching.

### Fixed

- A completed matching candidate survives another worker's returned error; the error remains a diagnostic.

- Blocked progress and closed pipes no longer delay saving a winner; final delivery failures return status 3 for a saved identity.
- Persistence rechecks the pattern, verifies exact bytes, preserves complete temporaries, detects hard-link corruption, and bounds retained recovery files.
- Explicit recovery discard returns cancellation status 130 even when unverified files and warnings remain.
- Directory-sync limitations preserve other errors; artifact smoke accepts only the explicitly reported Windows durability limitation.
- Preflight exercises writes, sync, publication and read-back before searching. Moved output directories remain anchored and are reported as saved deviations.

### Added

- Preflighted fallback output and bounded or unlimited save retries with fresh two-interrupt discard confirmation.
- SIGHUP/SIGTERM/SIGINT cancellation, explicit recovery discard, and stable saved/deviation/cancellation exit statuses.

- Search attempt and time limits with exit status 4; completed in-flight winners are preserved independently of search limits.

- The default segmented generator uses independent OS-backed draws for both inputs and refreshes the discarded X25519 half every 65,536 candidates; `--generator independent` remains available.
- Corpus differential, segment-boundary, later-winner, entropy-accounting and zero steady-state-allocation checks cover the segmented path, including startup self-testing.

- Public-only `--inspect` validates bounded regular files and preserves raw import encodings. Public sidecars now disclose only a quoted basename.

- The verifier reports absent/skipped metadata explicitly and gives specific remediation for legacy sidecars containing unlabelled private exports.

- Canonical Go module path and reproducible version stamping; `--version` remains available without cryptographic provider support.

### Security

- Refuse unsafe Unix directory ownership/write modes and check private-file ownership/mode before secret writes and during read-back. A portable explicit override reports accepted weaknesses; Windows retains acknowledgement of unverified ACLs.

- Current RNS/LXMF versions are resolved exactly per reference run, dependencies are hash-pinned, and wheel provenance is recorded. Daily compatibility checks have a separate trusted failure-notification workflow.

- Six native artifact smoke jobs, cross-host reproducibility checking, isolated attestation and owner-tag release publication use the exact same artifact bytes.
- CI selects the toolchain from `go.mod`, checks all target vets/module hygiene, and runs Python tests on Linux/macOS/Windows.
- Added security reporting, installation, checksum and attestation guidance.

- Public JSON results cover saved/deviating, cancelled, limited, failed, dry-run, benchmark, inspection and version modes, with checked output writes.
- Release toolchain moved to Go 1.27.2 to address reachable Windows `os.Root` advisory GO-2026-6604 found by the pinned scanner.

- Best-effort Unix core-dump suppression and Linux dumpability reduction occur before handling private input.
