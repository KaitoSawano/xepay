// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! ML-DSA-65 signature primitives for XEPAY.

pub mod address;
pub mod keypair;
pub mod sign;
pub mod verify;

/// Size of an ML-DSA-65 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// Size of an ML-DSA-65 secret key in bytes.
/// The crate stores the secret key as a 32-byte seed, which is the
/// canonical FIPS 204 representation.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of an ML-DSA-65 signature in bytes.
pub const SIGNATURE_SIZE: usize = 3309;
