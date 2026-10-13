# Security policy

Report suspected key exposure, unsafe persistence, entropy wiring or protocol
incompatibility privately. Use this repository's **Security → Report a
vulnerability** entry when available; otherwise contact the maintainer privately
through the [maintainer profile](https://github.com/CyberKiska). Do not attach
private identities or exports, crash/core dumps, shell history, or backups.
Provide a public test vector or a freshly generated disposable identity instead.

The current `main` revision and newest published release receive fixes. Older
releases and untested reference versions do not have a compatibility guarantee.
The default Go build uses only the standard library; Python reference packages
are test-time dependencies executed in disposable, read-only CI jobs.

In scope: unexpected overwrites or key disclosure, recoverable winner loss,
incorrect cryptographic derivation/import, insecure random-source wiring,
output-protection policy bypass, and build/release provenance failures.

The OS, administrator, filesystem and same-user processes are trusted. Unix
mode/owner checks do not verify ACLs or remote enforcement. Windows currently
requires explicit acknowledgement of unverified inherited ACLs. Memory clearing
and recovery do not guarantee protection against swap, snapshots, compiler
copies, runtime-fatal entropy failure, SIGQUIT/SIGKILL, blocked kernel I/O,
crashes or machine loss. Read-back is not proof of power-loss durability.
A vanity prefix does not authenticate a peer; compare the entire address.

Keep identities outside source control and automatically synchronized folders,
restrict their directory, and back up a verified result before using it. Do not
pass real private exports on command lines or share generated private sidecars.
