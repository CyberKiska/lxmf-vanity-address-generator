//! Compatibility corpus, golden fixture and allocation checks for the identity core.
//!
//! The vectors come from the Reticulum 1.4.2 reference (`testdata/*.json` in the repository),
//! converted by `scripts/gen_rust_test_vectors.py`. Everything here is public test data.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions; clippy.toml exempts only the latter"
)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use lxmf_vanity_core::identity::{CandidateInput, Identity};
use x25519_dalek::{PublicKey, StaticSecret};

const VECTORS: &str = include_str!("data/rns-identity-vectors.txt");
const GOLDEN: &str = include_str!("data/rns-1.4.2-golden.txt");

// ---- helpers ----

fn unhex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N, "wrong hex length");
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(pair).unwrap();
        *byte = u8::from_str_radix(digits, 16).unwrap();
    }
    out
}

fn input_from(bytes: &[u8; 64]) -> CandidateInput {
    let mut input = CandidateInput::zeroed();
    *input.as_mut_bytes() = *bytes;
    input
}

fn golden(key: &str) -> &'static str {
    GOLDEN
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
        .unwrap()
}

struct Vector {
    raw: [u8; 64],
    private: [u8; 64],
    public: [u8; 64],
    hash: [u8; 16],
    address: [u8; 16],
    signature: [u8; 64],
    shared: [u8; 32],
}

/// Returns (message bytes, peer private key, vectors).
fn corpus() -> (Vec<u8>, [u8; 32], Vec<Vector>) {
    let mut lines = VECTORS.lines();
    let message = lines.next().unwrap().strip_prefix("message ").unwrap();
    let message: Vec<u8> = (0..message.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&message[i..i + 2], 16).unwrap())
        .collect();
    let peer = unhex(lines.next().unwrap().strip_prefix("peer_private ").unwrap());
    let vectors = lines
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(fields.len(), 7, "vector line needs seven fields");
            Vector {
                raw: unhex(fields[0]),
                private: unhex(fields[1]),
                public: unhex(fields[2]),
                hash: unhex(fields[3]),
                address: unhex(fields[4]),
                signature: unhex(fields[5]),
                shared: unhex(fields[6]),
            }
        })
        .collect();
    (message, peer, vectors)
}

// ---- tests ----

// Go: TestReticulumIdentityCorpus
#[test]
fn corpus_vectors_match_reticulum_byte_for_byte() {
    let (message, peer_private, vectors) = corpus();
    assert_eq!(vectors.len(), 131);
    assert!(!message.is_empty());
    let peer_public = PublicKey::from(&StaticSecret::from(peer_private));
    for (index, vector) in vectors.iter().enumerate() {
        let identity = Identity::derive(&input_from(&vector.raw));

        let mut file = [0u8; 64];
        identity.private_file_bytes(&mut file);
        assert!(file == vector.private, "vector {index}: private file bytes");

        let public = identity.public();
        assert!(
            public.x25519_public[..] == vector.public[..32]
                && public.ed25519_public[..] == vector.public[32..],
            "vector {index}: public keys"
        );
        assert_eq!(public.identity_hash, vector.hash, "vector {index}: hash");
        assert_eq!(public.address, vector.address, "vector {index}: address");
        assert_eq!(identity.address(), &vector.address);

        let seed: [u8; 32] = file[32..].try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(&message);
        assert_eq!(
            signature.to_bytes(),
            vector.signature,
            "vector {index}: deterministic signature"
        );
        let reference = Signature::from_bytes(&vector.signature);
        assert!(
            signing_key
                .verifying_key()
                .verify(&message, &reference)
                .is_ok(),
            "vector {index}: reference signature does not verify"
        );
        assert!(
            identity.ed25519_public() == signing_key.verifying_key().as_bytes(),
            "vector {index}: verifying key"
        );

        let private: [u8; 32] = file[..32].try_into().unwrap();
        let shared = StaticSecret::from(private).diffie_hellman(&peer_public);
        assert!(
            shared.to_bytes() == vector.shared,
            "vector {index}: X25519 agreement"
        );

        assert_eq!(identity.verify_consistency(), Ok(()), "vector {index}");

        // The file bytes read back give the same public data, and are masked already.
        let (again, unmasked) = Identity::from_file_bytes(&file);
        assert_eq!(again, public, "vector {index}: read back");
        assert!(!unmasked, "vector {index}: stored private is masked");
        let (from_raw, raw_unmasked) = Identity::from_file_bytes(&vector.raw);
        assert_eq!(from_raw, public, "vector {index}: raw input");
        assert_eq!(
            raw_unmasked,
            vector.raw[..32] != vector.private[..32],
            "vector {index}: unmasked flag"
        );
    }
}

// Go: TestDeriveCandidateMatchesReticulum142GoldenVector, plus the fixture's round-trip claims
#[test]
fn golden_fixture_masked_and_unmasked_inputs_give_the_same_address() {
    assert_eq!(golden("rns_version"), "1.4.2");
    assert_eq!(golden("canonical_private_roundtrip"), "true");
    assert_eq!(golden("unmasked_private_roundtrip_preserved"), "true");
    assert_eq!(golden("unmasked_and_canonical_addresses_equal"), "true");

    let raw: [u8; 64] = unhex(golden("raw_candidate_input"));
    let mut canonical = [0u8; 64];
    canonical[..32].copy_from_slice(&unhex::<32>(golden("x25519_private")));
    canonical[32..].copy_from_slice(&unhex::<32>(golden("ed25519_seed")));
    assert_ne!(raw[..32], canonical[..32], "the raw input is unmasked");

    let from_raw = Identity::derive(&input_from(&raw));
    let from_canonical = Identity::derive(&input_from(&canonical));
    for identity in [&from_raw, &from_canonical] {
        assert_eq!(
            identity.x25519_public(),
            &unhex::<32>(golden("x25519_public"))
        );
        assert_eq!(
            identity.ed25519_public(),
            &unhex::<32>(golden("ed25519_public"))
        );
        assert_eq!(
            identity.identity_hash(),
            &unhex::<16>(golden("identity_hash"))
        );
        assert_eq!(identity.address(), &unhex::<16>(golden("lxmf_address")));
        let mut file = [0u8; 64];
        identity.private_file_bytes(&mut file);
        assert!(file == canonical, "stored private is canonical");
    }
    assert!(from_raw.public() == from_canonical.public());

    let (public, unmasked) = Identity::from_file_bytes(&raw);
    assert!(unmasked, "raw_candidate_input is unmasked");
    assert_eq!(public.address, unhex::<16>(golden("lxmf_address")));
    let (_, unmasked) = Identity::from_file_bytes(&canonical);
    assert!(!unmasked);
}
