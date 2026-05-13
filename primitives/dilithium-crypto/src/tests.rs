//! Characterization tests for the Dilithium crypto primitives.
//!
//! These tests pin down current on-chain behavior:
//!
//! * the `AccountId32` produced by deriving from a Dilithium public key,
//! * the SCALE discriminant of [`DilithiumSignatureScheme`] and [`DilithiumSigner`],
//! * the encoded layout (length) of the signature enum,
//! * the determinism of key derivation from a seed.
//!
//! Vectors are produced from deterministic seeds (e.g. `[0u8; 32]`).
//! They are NOT NIST KAT vectors. The intent is to lock the chain's current
//! observable behavior against accidental regressions during refactors,
//! dependency bumps, or enum reordering. A failing assertion here means the
//! change moves every Dilithium account's address or alters the on-chain
//! encoding of the signature enum, and must be treated as a chain-halting
//! review item, not a green light to update the constant.

use crate::types::{DilithiumSignatureScheme, DilithiumSigner};
use crate::DilithiumPair;
use codec::{Decode, Encode};
use sp_core::Pair;
use sp_runtime::{traits::IdentifyAccount, AccountId32};

const SEED_ZERO: [u8; 32] = [0u8; 32];
const SEED_ONE: [u8; 32] = [1u8; 32];

/// `AccountId32` for the public key derived from `SEED_ZERO`.
///
/// Captured from current code (`hash_bytes(pubkey)` via `qp_poseidon_core`).
/// Changing the AccountId derivation function will break this and every existing
/// Dilithium account address on the chain.
const SEED_ZERO_ACCOUNT_ID: [u8; 32] = [
	24, 131, 223, 42, 228, 125, 31, 212, 40, 166, 184, 35, 122, 215, 181, 156, 240, 250, 204, 202,
	172, 172, 69, 65, 239, 119, 88, 190, 68, 179, 195, 51,
];

/// `AccountId32` for the public key derived from `SEED_ONE`.
const SEED_ONE_ACCOUNT_ID: [u8; 32] = [
	48, 11, 182, 7, 186, 96, 232, 148, 97, 210, 249, 0, 86, 104, 35, 28, 235, 48, 35, 123, 51, 219,
	83, 166, 20, 22, 75, 133, 144, 150, 85, 25,
];

// --- Key derivation invariants ----------------------------------------------

#[test]
fn pair_from_seed_is_deterministic() {
	let p1 = DilithiumPair::from_seed_slice(&SEED_ZERO).expect("seed valid");
	let p2 = DilithiumPair::from_seed_slice(&SEED_ZERO).expect("seed valid");
	assert_eq!(p1.public().as_ref(), p2.public().as_ref());
}

#[test]
fn pubkey_has_expected_byte_length() {
	let p = DilithiumPair::from_seed_slice(&SEED_ZERO).expect("seed valid");
	assert_eq!(p.public().as_ref().len(), crate::PUB_KEY_BYTES);
}

// --- AccountId derivation: frozen vectors -----------------------------------

#[test]
fn seed_zero_derives_known_account_id() {
	let p = DilithiumPair::from_seed_slice(&SEED_ZERO).expect("seed valid");
	let acc: AccountId32 = p.public().into_account();
	let bytes: &[u8; 32] = acc.as_ref();
	assert_eq!(
		bytes, &SEED_ZERO_ACCOUNT_ID,
		"AccountId derivation for SEED_ZERO has changed; this moves every existing \
		 Dilithium address on the chain. See tests.rs documentation before updating."
	);
}

#[test]
fn seed_one_derives_known_account_id() {
	let p = DilithiumPair::from_seed_slice(&SEED_ONE).expect("seed valid");
	let acc: AccountId32 = p.public().into_account();
	let bytes: &[u8; 32] = acc.as_ref();
	assert_eq!(bytes, &SEED_ONE_ACCOUNT_ID);
}

#[test]
fn distinct_seeds_yield_distinct_account_ids() {
	let acc0: AccountId32 =
		DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap().public().into_account();
	let acc1: AccountId32 =
		DilithiumPair::from_seed_slice(&SEED_ONE).unwrap().public().into_account();
	assert_ne!(acc0, acc1);
}

#[test]
fn account_id_derivation_is_idempotent() {
	let pubkey = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap().public();
	let a: AccountId32 = pubkey.clone().into_account();
	let b: AccountId32 = pubkey.into_account();
	assert_eq!(a, b);
}

// --- SCALE encoding invariants ----------------------------------------------

#[test]
fn signature_scheme_dilithium_variant_byte_is_zero() {
	let pair = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap();
	let sig = pair.sign(b"variant-byte-test");
	let scheme = DilithiumSignatureScheme::Dilithium(sig);
	let encoded = scheme.encode();
	assert!(!encoded.is_empty(), "encoded signature scheme is empty");
	assert_eq!(
		encoded[0], 0x00,
		"`DilithiumSignatureScheme::Dilithium` must remain at SCALE variant index 0. \
		 Adding new variants is fine; reordering breaks every existing signature."
	);
}

#[test]
fn signer_dilithium_variant_byte_is_zero() {
	let pubkey = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap().public();
	let signer = DilithiumSigner::Dilithium(pubkey);
	let encoded = signer.encode();
	assert!(!encoded.is_empty());
	assert_eq!(
		encoded[0], 0x00,
		"`DilithiumSigner::Dilithium` must remain at SCALE variant index 0."
	);
}

#[test]
fn signature_scheme_encoded_length_matches_layout() {
	// Expected: 1 byte SCALE discriminant + SIGNATURE_BYTES + PUB_KEY_BYTES
	let pair = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap();
	let sig = pair.sign(b"length-check");
	let scheme = DilithiumSignatureScheme::Dilithium(sig);
	let encoded = scheme.encode();
	let expected = 1 + crate::SIGNATURE_BYTES + crate::PUB_KEY_BYTES;
	assert_eq!(encoded.len(), expected);
}

#[test]
fn signature_scheme_scale_roundtrip() {
	let pair = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap();
	let sig = pair.sign(b"roundtrip");
	let scheme = DilithiumSignatureScheme::Dilithium(sig);
	let bytes = scheme.encode();
	let decoded =
		DilithiumSignatureScheme::decode(&mut &bytes[..]).expect("decode round-trips");
	assert_eq!(scheme, decoded);
}

#[test]
fn signer_scale_roundtrip() {
	let pubkey = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap().public();
	let signer = DilithiumSigner::Dilithium(pubkey);
	let bytes = signer.encode();
	let decoded = DilithiumSigner::decode(&mut &bytes[..]).expect("decode round-trips");
	assert_eq!(signer, decoded);
}

// --- suite_tag invariants ----------------------------------------------------

#[test]
fn suite_tag_dilithium_is_zero() {
	let tag: u8 = crate::suite_tag::DILITHIUM;
	assert_eq!(
		tag, 0x00,
		"`suite_tag::DILITHIUM` must equal the SCALE discriminant of \
		 `DilithiumSignatureScheme::Dilithium` so that on-chain bytes and \
		 the off-chain suite identifier agree."
	);
}

#[test]
fn suite_tag_matches_signature_scheme_variant_byte() {
	let pair = DilithiumPair::from_seed_slice(&SEED_ZERO).unwrap();
	let sig = pair.sign(b"suite-tag-match");
	let scheme = DilithiumSignatureScheme::Dilithium(sig);
	let encoded = scheme.encode();
	assert_eq!(encoded[0], crate::suite_tag::DILITHIUM);
}
