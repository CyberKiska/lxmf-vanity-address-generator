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
- Preflight exercises writes, sync, publication and read-back before searching. Moved output directories remain anchored and are reported as saved deviations.

### Added

- Preflighted fallback output and bounded or unlimited save retries with fresh two-interrupt discard confirmation.
- SIGHUP/SIGTERM/SIGINT cancellation, explicit recovery discard, and stable saved/deviation/cancellation exit statuses.

- Search attempt and time limits with exit status 4; completed in-flight winners are preserved independently of search limits.
