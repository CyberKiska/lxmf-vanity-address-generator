//! Identity derivation: the keys, hash and LXMF address of one 64-byte input.
//!
//! Port of `identity.go`. The byte layout is:
//!
//! ```text
//! x25519_private = clamp(input[0..32])     (stored masked)
//! ed25519_seed   = input[32..64]
//! public         = x25519_public || ed25519_public
//! identity_hash  = SHA-256(public)[..16]
//! address        = SHA-256(NAME_HASH || identity_hash)[..16]
//! ```
//!
//! [`CandidateInput`] and [`Identity`] hold secrets: they have no `Debug`,
//! `Display`, `Clone`, `Copy`, `Hash` or serialization, and they zero their
//! secret bytes when dropped. [`PublicIdentity`] holds public data only.
//!
//! ```compile_fail,E0277
//! fn needs<T: Clone>() {}
//! needs::<lxmf_vanity_core::identity::CandidateInput>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: Copy>() {}
//! needs::<lxmf_vanity_core::identity::CandidateInput>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Debug>() {}
//! needs::<lxmf_vanity_core::identity::CandidateInput>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Display>() {}
//! needs::<lxmf_vanity_core::identity::CandidateInput>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: std::hash::Hash>() {}
//! needs::<lxmf_vanity_core::identity::CandidateInput>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: Clone>() {}
//! needs::<lxmf_vanity_core::identity::Identity>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: Copy>() {}
//! needs::<lxmf_vanity_core::identity::Identity>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Debug>() {}
//! needs::<lxmf_vanity_core::identity::Identity>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: std::fmt::Display>() {}
//! needs::<lxmf_vanity_core::identity::Identity>();
//! ```
//!
//! ```compile_fail,E0277
//! fn needs<T: std::hash::Hash>() {}
//! needs::<lxmf_vanity_core::identity::Identity>();
//! ```

use core::fmt;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// First 10 bytes of SHA-256 of `"lxmf.delivery"` (Go `lxmfNameHash`).
pub const NAME_HASH: [u8; 10] = [0x6e, 0xc6, 0x0b, 0xc3, 0x18, 0xe2, 0xc0, 0xf0, 0xd9, 0x08];

/// Port of `clampX25519`.
pub(crate) fn clamp_x25519(private: &mut [u8; 32]) {
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
}

/// Raw 64 candidate bytes (X25519 half, then Ed25519 seed). Secret.
pub struct CandidateInput([u8; 64]);

impl CandidateInput {
    /// An all-zero input, to be filled through [`CandidateInput::as_mut_bytes`].
    pub fn zeroed() -> Self {
        Self([0; 64])
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; 64] {
        &mut self.0
    }
}

impl Drop for CandidateInput {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The four public values of an identity. Public data only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub x25519_public: [u8; 32],
    pub ed25519_public: [u8; 32],
    pub identity_hash: [u8; 16],
    pub address: [u8; 16],
}

/// A derived identity (port of Go's `Identity`). Holds secrets.
pub struct Identity {
    /// Always stored masked.
    x25519_private: [u8; 32],
    x25519_public: [u8; 32],
    ed25519_seed: [u8; 32],
    ed25519_public: [u8; 32],
    identity_hash: [u8; 16],
    address: [u8; 16],
}

/// Returned by [`Identity::verify_consistency`]. The message is part of the
/// contract (Go `validateIdentityConsistency`).
#[derive(Debug, PartialEq, Eq)]
pub struct ConsistencyError;

impl fmt::Display for ConsistencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "identity fields are inconsistent with the private key material; refusing to save",
        )
    }
}

impl std::error::Error for ConsistencyError {}

/// X25519 public key through the precomputed base-point table (not the
/// Montgomery ladder). The dalek secret zeroizes itself when dropped.
fn x25519_public(masked_private: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*masked_private);
    PublicKey::from(&secret).to_bytes()
}

impl Identity {
    /// Port of `deriveCandidate`. Does not allocate.
    pub fn derive(input: &CandidateInput) -> Identity {
        let mut identity = Identity {
            x25519_private: [0; 32],
            x25519_public: [0; 32],
            ed25519_seed: [0; 32],
            ed25519_public: [0; 32],
            identity_hash: [0; 16],
            address: [0; 16],
        };
        // Secrets are written straight into the identity, so the only extra
        // copy is the one dalek makes (and wipes) inside `x25519_public`.
        identity.x25519_private.copy_from_slice(&input.0[..32]);
        clamp_x25519(&mut identity.x25519_private);
        identity.ed25519_seed.copy_from_slice(&input.0[32..]);
        identity.x25519_public = x25519_public(&identity.x25519_private);
        identity.refresh_signing_half();
        identity
    }

    /// Port of `rederiveSigningHalf`: replace the seed and recompute the
    /// Ed25519 public key, hash and address, keeping the X25519 half.
    /// Does not allocate.
    pub fn rederive_signing_half(&mut self, new_seed: &[u8; 32]) {
        self.ed25519_seed = *new_seed;
        self.refresh_signing_half();
    }

    /// Everything that depends on `ed25519_seed` and the X25519 public key.
    fn refresh_signing_half(&mut self) {
        // `SigningKey` zeroizes itself when dropped at the end of this block.
        self.ed25519_public = SigningKey::from_bytes(&self.ed25519_seed)
            .verifying_key()
            .to_bytes();
        let mut public = [0u8; 64];
        public[..32].copy_from_slice(&self.x25519_public);
        public[32..].copy_from_slice(&self.ed25519_public);
        self.identity_hash
            .copy_from_slice(&Sha256::digest(public)[..16]);
        let mut material = [0u8; 26];
        material[..10].copy_from_slice(&NAME_HASH);
        material[10..].copy_from_slice(&self.identity_hash);
        self.address
            .copy_from_slice(&Sha256::digest(material)[..16]);
    }

    /// Port of the inspection path: derive from file bytes that may carry an
    /// unmasked X25519 half. Returns the public values and whether
    /// `clamp(bytes[0..32]) != bytes[0..32]`. Nothing secret is kept.
    pub fn from_file_bytes(bytes: &[u8; 64]) -> (PublicIdentity, bool) {
        let mut input = CandidateInput::zeroed();
        input.0.copy_from_slice(bytes);
        let identity = Identity::derive(&input);
        // Equivalent to comparing with the clamped bytes; the unit tests
        // check it against `clamp_x25519` for every value of both bytes.
        let unmasked = bytes[0] & 7 != 0 || bytes[31] & 0xc0 != 0x40;
        (identity.public(), unmasked)
    }

    /// Port of `validateIdentityConsistency`: re-derive from the stored
    /// private halves and compare all six fields in constant time, without
    /// returning early. A stored X25519 value that is not masked fails.
    pub fn verify_consistency(&self) -> Result<(), ConsistencyError> {
        let mut input = CandidateInput::zeroed();
        input.0[..32].copy_from_slice(&self.x25519_private);
        input.0[32..].copy_from_slice(&self.ed25519_seed);
        let expected = Identity::derive(&input);
        if bool::from(self.ct_eq_all(&expected)) {
            Ok(())
        } else {
            Err(ConsistencyError)
        }
    }

    /// Compares all six fields in Go's order, accumulating every result.
    pub(crate) fn ct_eq_all(&self, other: &Identity) -> Choice {
        let mut equal = self.x25519_private[..].ct_eq(&other.x25519_private[..]);
        equal &= self.ed25519_seed[..].ct_eq(&other.ed25519_seed[..]);
        equal &= self.x25519_public[..].ct_eq(&other.x25519_public[..]);
        equal &= self.ed25519_public[..].ct_eq(&other.ed25519_public[..]);
        equal &= self.identity_hash[..].ct_eq(&other.identity_hash[..]);
        equal &= self.address[..].ct_eq(&other.address[..]);
        equal
    }

    /// Builds an identity from given values without deriving or checking
    /// them. Only the self-test uses it, for its public test vector.
    pub(crate) fn from_fields(
        x25519_private: &[u8; 32],
        x25519_public: &[u8; 32],
        ed25519_seed: &[u8; 32],
        ed25519_public: &[u8; 32],
        identity_hash: &[u8; 16],
        address: &[u8; 16],
    ) -> Identity {
        Identity {
            x25519_private: *x25519_private,
            x25519_public: *x25519_public,
            ed25519_seed: *ed25519_seed,
            ed25519_public: *ed25519_public,
            identity_hash: *identity_hash,
            address: *address,
        }
    }

    /// Writes the 64-byte private file content (`x25519_private || seed`).
    /// The caller owns `out` and must wipe it.
    pub fn private_file_bytes(&self, out: &mut [u8; 64]) {
        out[..32].copy_from_slice(&self.x25519_private);
        out[32..].copy_from_slice(&self.ed25519_seed);
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            x25519_public: self.x25519_public,
            ed25519_public: self.ed25519_public,
            identity_hash: self.identity_hash,
            address: self.address,
        }
    }

    pub fn x25519_public(&self) -> &[u8; 32] {
        &self.x25519_public
    }

    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_public
    }

    pub fn identity_hash(&self) -> &[u8; 16] {
        &self.identity_hash
    }

    pub fn address(&self) -> &[u8; 16] {
        &self.address
    }

    /// Port of `wipeIdentitySecrets`.
    fn wipe(&mut self) {
        self.x25519_private.zeroize();
        self.ed25519_seed.zeroize();
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_from(bytes: &[u8; 64]) -> CandidateInput {
        let mut input = CandidateInput::zeroed();
        *input.as_mut_bytes() = *bytes;
        input
    }

    fn sequence_input() -> CandidateInput {
        input_from(&core::array::from_fn(|i| i as u8))
    }

    #[test]
    fn name_hash_is_sha256_of_lxmf_delivery_prefix() {
        assert_eq!(NAME_HASH[..], Sha256::digest("lxmf.delivery")[..10]);
    }

    // Go: TestClampX25519ProducesCanonicalPrivateEncoding
    #[test]
    fn clamp_matches_go_for_every_first_and_last_byte() {
        for first in 0..=255u8 {
            for last in 0..=255u8 {
                let mut private = [0x5a; 32];
                private[0] = first;
                private[31] = last;
                clamp_x25519(&mut private);
                assert_eq!(private[0], first & 248);
                assert_eq!(private[31], (last & 127) | 64);
                assert_eq!(private[1..31], [0x5a; 30]);
            }
        }
    }

    #[test]
    fn derive_masks_the_x25519_half_and_keeps_the_seed() {
        for first in 0..=255u8 {
            for last in [0x00, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xff] {
                let mut bytes: [u8; 64] = core::array::from_fn(|i| 0x30 + i as u8);
                bytes[0] = first;
                bytes[31] = last;
                let identity = Identity::derive(&input_from(&bytes));
                let mut file = [0; 64];
                identity.private_file_bytes(&mut file);
                assert_eq!(file[0], first & 248);
                assert_eq!(file[31], (last & 127) | 64);
                assert_eq!(file[1..31], bytes[1..31]);
                assert_eq!(file[32..], bytes[32..]);
            }
        }
    }

    #[test]
    fn unmasked_flag_equals_clamp_difference_for_every_first_and_last_byte() {
        for first in 0..=255u8 {
            for last in 0..=255u8 {
                let mut private = [0; 32];
                private[0] = first;
                private[31] = last;
                let mut clamped = private;
                clamp_x25519(&mut clamped);
                let flag = first & 7 != 0 || last & 0xc0 != 0x40;
                assert_eq!(flag, clamped != private);
            }
        }
    }

    #[test]
    fn from_file_bytes_reports_unmasked_input_and_keeps_public_data() {
        let mut bytes: [u8; 64] = core::array::from_fn(|i| i as u8);
        let identity = Identity::derive(&input_from(&bytes));
        let (public, unmasked) = Identity::from_file_bytes(&bytes);
        assert_eq!(public, identity.public());
        assert!(unmasked, "0x1f has bit 6 clear and 0x01 has low bits set");
        let mut masked = [0; 64];
        identity.private_file_bytes(&mut masked);
        let (same, unmasked) = Identity::from_file_bytes(&masked);
        assert_eq!(same, public);
        assert!(!unmasked);
        bytes[31] = 0x40;
        bytes[0] = 0;
        assert!(!Identity::from_file_bytes(&bytes).1);
    }

    #[test]
    fn rederived_signing_half_equals_a_fresh_derivation() {
        let mut input = sequence_input();
        let mut identity = Identity::derive(&input);
        for round in 1..=3u8 {
            for byte in &mut input.as_mut_bytes()[32..] {
                *byte = byte.wrapping_add(round).rotate_left(3);
            }
            let seed: [u8; 32] = input.as_bytes()[32..].try_into().unwrap();
            identity.rederive_signing_half(&seed);
            let fresh = Identity::derive(&input);
            assert!(bool::from(identity.ct_eq_all(&fresh)));
            assert!(identity.verify_consistency().is_ok());
        }
    }

    fn tampered(change: impl FnOnce(&mut Identity)) -> Identity {
        let mut identity = Identity::derive(&sequence_input());
        assert!(identity.verify_consistency().is_ok());
        change(&mut identity);
        identity
    }

    // Go: TestSaveIdentityRejectsInconsistentDerivedFields
    #[test]
    fn consistency_fails_when_any_one_field_is_tampered() {
        type Tamper = fn(&mut Identity);
        let cases: [(&str, Tamper); 6] = [
            ("x25519_private", |i| i.x25519_private[5] ^= 1),
            ("ed25519_seed", |i| i.ed25519_seed[5] ^= 1),
            ("x25519_public", |i| i.x25519_public[5] ^= 1),
            ("ed25519_public", |i| i.ed25519_public[5] ^= 1),
            ("identity_hash", |i| i.identity_hash[5] ^= 1),
            ("address", |i| i.address[5] ^= 1),
        ];
        for (name, change) in cases {
            let error = tampered(change).verify_consistency().unwrap_err();
            assert_eq!(
                error.to_string(),
                "identity fields are inconsistent with the private key material; refusing to save",
                "{name}"
            );
        }
    }

    #[test]
    fn consistency_fails_for_an_unmasked_stored_private_value() {
        let cases: [fn(&mut Identity); 3] = [
            |i| i.x25519_private[0] |= 1,
            |i| i.x25519_private[31] |= 0x80,
            |i| i.x25519_private[31] &= !0x40,
        ];
        for change in cases {
            assert!(tampered(change).verify_consistency().is_err());
        }
    }

    #[test]
    fn wipe_zeroes_both_secret_halves() {
        let mut identity = Identity::derive(&sequence_input());
        identity.wipe();
        let mut file = [0xff; 64];
        identity.private_file_bytes(&mut file);
        assert_eq!(file, [0; 64]);
    }
}
