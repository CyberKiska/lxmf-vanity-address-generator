//! Startup known-answer self-test. Port of `selftest.go`.

use core::fmt;

use zeroize::Zeroize;

use crate::identity::{CandidateInput, Identity};

// PUBLIC TEST VECTOR, never use as an identity.
const GOLDEN_X25519_PRIVATE: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x5f,
];
const GOLDEN_X25519_PUBLIC: [u8; 32] = [
    0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62, 0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a, 0x6e,
    0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a, 0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f,
];
const GOLDEN_ED25519_SEED: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const GOLDEN_ED25519_PUBLIC: [u8; 32] = [
    0x29, 0xac, 0xba, 0xe1, 0x41, 0xbc, 0xca, 0xf0, 0xb2, 0x2e, 0x1a, 0x94, 0xd3, 0x4d, 0x0b, 0xc7,
    0x36, 0x1e, 0x52, 0x6d, 0x0b, 0xfe, 0x12, 0xc8, 0x97, 0x94, 0xbc, 0x93, 0x22, 0x96, 0x6d, 0xd7,
];
const GOLDEN_IDENTITY_HASH: [u8; 16] = [
    0xac, 0xa3, 0x1a, 0xf0, 0x44, 0x1d, 0x81, 0xdb, 0xec, 0x71, 0xe8, 0x2d, 0xa0, 0xb4, 0xb5, 0xf5,
];
const GOLDEN_LXMF_ADDRESS: [u8; 16] = [
    0xfa, 0xe3, 0x21, 0xc4, 0x42, 0xe3, 0xc9, 0xbd, 0xcd, 0x7a, 0x3e, 0x79, 0xd8, 0x50, 0xe0, 0x3c,
];

/// Why the self-test failed. The messages are part of the contract.
#[derive(Debug, PartialEq, Eq)]
pub enum SelfTestError {
    KnownAnswerMismatch,
    SegmentedDerivationMismatch,
}

impl fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KnownAnswerMismatch => "self-test failed: known-answer mismatch",
            Self::SegmentedDerivationMismatch => "self-test failed: segmented derivation mismatch",
        })
    }
}

impl std::error::Error for SelfTestError {}

/// The signing-half step under test: `Identity::rederive_signing_half` in
/// production, a deliberately broken one in the tests.
pub(crate) type SigningHalfTransform = fn(&mut Identity, &[u8; 32]);

/// Port of `knownAnswerIdentity`.
fn known_answer_identity() -> Identity {
    Identity::from_fields(
        &GOLDEN_X25519_PRIVATE,
        &GOLDEN_X25519_PUBLIC,
        &GOLDEN_ED25519_SEED,
        &GOLDEN_ED25519_PUBLIC,
        &GOLDEN_IDENTITY_HASH,
        &GOLDEN_LXMF_ADDRESS,
    )
}

/// Port of `selfTest(knownAnswerIdentity())`.
pub fn self_test() -> Result<(), SelfTestError> {
    self_test_with_transform(&known_answer_identity(), Identity::rederive_signing_half)
}

/// Port of `selfTestWithTransform`.
pub(crate) fn self_test_with_transform(
    expected: &Identity,
    transform: SigningHalfTransform,
) -> Result<(), SelfTestError> {
    let mut raw = CandidateInput::zeroed();
    for (index, byte) in raw.as_mut_bytes().iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut actual = Identity::derive(&raw);
    if !bool::from(actual.ct_eq_all(expected)) {
        return Err(SelfTestError::KnownAnswerMismatch);
    }
    // Continue the already verified segment just as a worker would.
    for byte in &mut raw.as_mut_bytes()[32..] {
        *byte ^= 0xa5;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw.as_bytes()[32..]);
    transform(&mut actual, &seed);
    seed.zeroize();
    let independent = Identity::derive(&raw);
    if !bool::from(actual.ct_eq_all(&independent)) {
        return Err(SelfTestError::SegmentedDerivationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // Go: TestGoldenConstantsMatchPinnedFixture
    #[test]
    fn golden_constants_match_the_pinned_fixture() {
        let fixture = include_str!("../tests/data/rns-1.4.2-golden.txt");
        let value = |key: &str| {
            fixture
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
                .unwrap()
        };
        assert_eq!(value("rns_version"), "1.4.2");
        assert_eq!(value("x25519_private"), hex_of(&GOLDEN_X25519_PRIVATE));
        assert_eq!(value("x25519_public"), hex_of(&GOLDEN_X25519_PUBLIC));
        assert_eq!(value("ed25519_seed"), hex_of(&GOLDEN_ED25519_SEED));
        assert_eq!(value("ed25519_public"), hex_of(&GOLDEN_ED25519_PUBLIC));
        assert_eq!(value("identity_hash"), hex_of(&GOLDEN_IDENTITY_HASH));
        assert_eq!(value("lxmf_address"), hex_of(&GOLDEN_LXMF_ADDRESS));
        assert_eq!(hex(value("lxmf_name_hash")), crate::identity::NAME_HASH);
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Go: TestKnownAnswerSelfTest
    #[test]
    fn self_test_passes_and_rejects_a_corrupt_expectation() {
        assert_eq!(self_test(), Ok(()));
        let mut address = GOLDEN_LXMF_ADDRESS;
        address[0] ^= 1;
        let corrupt = Identity::from_fields(
            &GOLDEN_X25519_PRIVATE,
            &GOLDEN_X25519_PUBLIC,
            &GOLDEN_ED25519_SEED,
            &GOLDEN_ED25519_PUBLIC,
            &GOLDEN_IDENTITY_HASH,
            &address,
        );
        let error = self_test_with_transform(&corrupt, Identity::rederive_signing_half);
        assert_eq!(error, Err(SelfTestError::KnownAnswerMismatch));
        assert_eq!(
            SelfTestError::KnownAnswerMismatch.to_string(),
            "self-test failed: known-answer mismatch"
        );
    }

    // Go: TestSegmentedSelfTestDetectsBrokenTransform
    #[test]
    fn self_test_detects_broken_signing_half_transforms() {
        let broken: [SigningHalfTransform; 2] = [
            // Forgets to re-derive anything.
            |_, _| {},
            // Re-derives from a seed with one bit changed.
            |identity, seed| {
                let mut wrong = *seed;
                wrong[0] ^= 1;
                identity.rederive_signing_half(&wrong);
            },
        ];
        for transform in broken {
            assert_eq!(
                self_test_with_transform(&known_answer_identity(), transform),
                Err(SelfTestError::SegmentedDerivationMismatch)
            );
        }
        assert_eq!(
            SelfTestError::SegmentedDerivationMismatch.to_string(),
            "self-test failed: segmented derivation mismatch"
        );
    }
}
