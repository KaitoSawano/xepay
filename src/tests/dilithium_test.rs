// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use xepay::dilithium::{address, keypair::KeyPair, sign, verify};
use xepay_crypto::sha3_256_hex;

#[test]
fn generate_keypair_has_correct_lengths() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    assert_eq!(kp.public_key.len(), 1952); // ML-DSA-65 public key size
    assert_eq!(kp.secret_key.len(), 32);   // 32-byte seed
}

#[test]
fn sign_and_verify_roundtrip() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let msg_hex = sha3_256_hex(b"hello xepay");
    let msg = hex::decode(&msg_hex).expect("hex decode failed");
    
    let sig = sign::sign(&kp.secret_key, &msg).expect("signing failed");
    assert_eq!(sig.len(), 3309); // ML-DSA-65 signature size
    
    assert!(verify::verify(&kp.public_key, &msg, &sig));
}

#[test]
fn verify_rejects_wrong_message() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let msg_hex = sha3_256_hex(b"hello xepay");
    let msg = hex::decode(&msg_hex).expect("hex decode failed");
    let sig = sign::sign(&kp.secret_key, &msg).expect("signing failed");
    
    let other = hex::decode(&sha3_256_hex(b"other message")).expect("hex decode failed");
    assert!(!verify::verify(&kp.public_key, &other, &sig));
}

#[test]
fn address_is_deterministic() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let a1 = address::address_from_public_key(&kp.public_key).expect("address failed");
    let a2 = address::address_from_public_key(&kp.public_key).expect("address failed");
    assert_eq!(a1, a2);
}
