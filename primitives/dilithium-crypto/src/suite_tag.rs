//! Signature-suite tag constants.
//!
//! Each tag is the SCALE discriminant of the corresponding variant of
//! [`crate::types::DilithiumSignatureScheme`] and [`crate::types::DilithiumSigner`].
//! Off-chain callers (key generation, address derivation for future schemes,
//! address-format display) MUST use these constants instead of repeating the
//! literal index; this keeps the off-chain suite identifier in lock-step with
//! the on-chain encoding.
//!
//! # Adding a new scheme
//!
//! 1. Append the new variant to both `DilithiumSignatureScheme` and
//!    `DilithiumSigner` at the **end** of the enum. Never reorder existing
//!    variants; the SCALE encoding is index-positional and reordering would
//!    invalidate every previously-signed extrinsic in chain history.
//! 2. Add the matching `pub const NAME: u8 = N;` here, where `N` is the
//!    declaration index of the new variant.
//! 3. Add a regression test in `tests.rs` asserting that the new variant
//!    encodes with the expected leading byte.

/// SCALE discriminant for the Dilithium (ML-DSA-87) variant. Variant index 0.
pub const DILITHIUM: u8 = 0x00;
