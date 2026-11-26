//! Version text and build information.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the console entry point (P1-09)")
)]

use std::sync::OnceLock;

/// Port of version.go `buildVersion`: a release build sets `LXMF_VANITY_VERSION`.
pub(crate) fn version_string() -> &'static str {
    match option_env!("LXMF_VANITY_VERSION") {
        Some(v) if !v.is_empty() => v,
        _ => env!("CARGO_PKG_VERSION"),
    }
}

/// Port of version.go `versionText`. Go prints its toolchain (`go1.x.y`);
/// this prints `rustc <version>` (`DEV-version-text`).
pub(crate) fn version_text() -> String {
    format!(
        "lxmf-vanity {} (rustc {} {GOOS}/{GOARCH})\n",
        version_string(),
        env!("LXMF_VANITY_RUSTC_VERSION")
    )
}

/// Rust `target_os` to Go `GOOS`.
pub(crate) const fn go_os(rust_os: &str) -> Option<&'static str> {
    match rust_os.as_bytes() {
        b"linux" => Some("linux"),
        b"macos" => Some("darwin"),
        b"windows" => Some("windows"),
        _ => None,
    }
}

/// Rust `target_arch` to Go `GOARCH`.
pub(crate) const fn go_arch(rust_arch: &str) -> Option<&'static str> {
    match rust_arch.as_bytes() {
        b"x86_64" => Some("amd64"),
        b"aarch64" => Some("arm64"),
        _ => None,
    }
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!(
    "unsupported target: lxmf-vanity supports linux, macos and windows on x86_64 and aarch64"
);

// The fallback is unreachable: `compile_error!` above rejects other targets.
const GOOS: &str = match go_os(std::env::consts::OS) {
    Some(s) => s,
    None => "unsupported",
};
const GOARCH: &str = match go_arch(std::env::consts::ARCH) {
    Some(s) => s,
    None => "unsupported",
};

/// Build facts for the release bundles. The build script refuses every backend
/// override, so the backends are always the defaults.
pub(crate) fn build_info() -> &'static str {
    static INFO: OnceLock<String> = OnceLock::new();
    INFO.get_or_init(|| {
        let target = env!("LXMF_VANITY_TARGET");
        let panic = if cfg!(panic = "abort") {
            "abort"
        } else {
            "unwind"
        };
        format!(
            "version: {}\nrustc: {}\ntarget: {target}\nopt-level: {}\npanic: {panic}\n\
             getrandom backend: default for {target}\n\
             curve25519-dalek backend: default for {target}\n\
             curve25519-dalek bits: default for {target}\n",
            version_string(),
            env!("LXMF_VANITY_RUSTC_VERSION"),
            env!("LXMF_VANITY_OPT_LEVEL"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Go: TestVersionBypassesSearchAndProviderValidation (text part)
    #[test]
    fn version_text_names_program_version_compiler_and_target() {
        let text = version_text();
        assert!(text.starts_with(&format!("lxmf-vanity {} (rustc ", version_string())));
        assert!(text.ends_with(&format!(" {GOOS}/{GOARCH})\n")));
        assert_eq!(text.matches('\n').count(), 1);
    }

    // scripts/smoke_artifact.py: the version and "<goos>/<goarch>" must be present.
    #[test]
    fn version_text_satisfies_the_artifact_smoke_check() {
        let text = version_text();
        assert!(text.contains(version_string()));
        assert!(text.contains(&format!("{GOOS}/{GOARCH}")));
    }

    #[test]
    fn rustc_version_is_the_bare_version_number() {
        let v = env!("LXMF_VANITY_RUSTC_VERSION");
        assert!(v.starts_with(|c: char| c.is_ascii_digit()), "{v}");
        assert!(!v.contains(char::is_whitespace), "{v}");
        assert!(!v.contains("Homebrew"));
    }

    #[test]
    fn default_version_is_the_package_version() {
        if option_env!("LXMF_VANITY_VERSION").is_none() {
            assert_eq!(version_string(), "2.0.0-dev");
        }
    }

    #[test]
    fn the_five_release_targets_map_to_go_names() {
        let targets = [
            ("linux", "x86_64", "linux", "amd64"),
            ("linux", "aarch64", "linux", "arm64"),
            ("macos", "aarch64", "darwin", "arm64"),
            ("windows", "x86_64", "windows", "amd64"),
            ("windows", "aarch64", "windows", "arm64"),
        ];
        for (os, arch, goos, goarch) in targets {
            assert_eq!(go_os(os), Some(goos));
            assert_eq!(go_arch(arch), Some(goarch));
        }
    }

    #[test]
    fn other_systems_and_architectures_have_no_mapping() {
        for os in ["freebsd", "darwin", "ios", "android", "", "Linux"] {
            assert_eq!(go_os(os), None, "{os}");
        }
        for arch in ["x86", "arm", "riscv64", "amd64", "arm64", ""] {
            assert_eq!(go_arch(arch), None, "{arch}");
        }
    }

    #[test]
    fn build_info_lists_every_recorded_fact() {
        let info = build_info();
        for key in [
            "version: ",
            "rustc: ",
            "target: ",
            "opt-level: ",
            "panic: ",
            "getrandom backend: default for ",
            "curve25519-dalek backend: default for ",
            "curve25519-dalek bits: default for ",
        ] {
            assert!(info.contains(key), "missing {key:?}");
        }
        assert!(info.contains(&format!("version: {}\n", version_string())));
        assert!(info.ends_with('\n'));
    }

    // Manual check (cannot run inside `cargo test`): a backend override must stop
    // the build, naming the variable. From the `rust` directory:
    //
    //   RUSTFLAGS='--cfg getrandom_backend="custom"' cargo build -p lxmf-vanity-cli
    //   RUSTFLAGS='--cfg curve25519_dalek_backend="serial"' cargo build -p lxmf-vanity-cli
    //   RUSTFLAGS='--cfg curve25519_dalek_bits="32"' cargo build -p lxmf-vanity-cli
    //
    // Each must fail with "lxmf-vanity build script: CARGO_CFG_<NAME> is set ...".
}
