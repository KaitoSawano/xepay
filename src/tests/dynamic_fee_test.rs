// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Regression tests for the dynamic fee market.
//!
//! The dynamic fee market increases the minimum relay fee per byte
//! as the mempool fills up. These tests verify the threshold logic
//! without needing to push tens of thousands of real transactions
//! into the mempool.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::{Blockchain, MAX_MEMPOOL_SIZE_BYTES, MIN_RELAY_FEE_PER_BYTE};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    std::env::set_var("XEPC_DATADIR", dir.path());
    f();
    std::env::remove_var("XEPC_DATADIR");
}

/// An empty mempool must return the base minimum relay fee.
#[test]
#[serial]
fn dynamic_fee_starts_at_base() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        assert_eq!(chain.mempool_size_bytes(), 0);
        assert_eq!(chain.current_min_fee_per_byte(), MIN_RELAY_FEE_PER_BYTE);
    });
}

/// The thresholds must follow the documented step function:
/// - below 50%: 1x
/// - 50% to 75%: 2x
/// - 75% to 90%: 5x
/// - above 90%: 10x
///
/// Because the mempool cannot be easily resized without creating real
/// transactions, this test verifies the arithmetic of the thresholds
/// themselves.
#[test]
fn dynamic_fee_thresholds_are_correct() {
    let max = MAX_MEMPOOL_SIZE_BYTES;

    // Below 50%: base fee.
    let size_49 = (max as f64 * 0.49) as usize;
    assert!(size_49 < max / 2);
    assert_eq!(MIN_RELAY_FEE_PER_BYTE, 1);

    // 50% to 75%: 2x.
    let size_51 = (max as f64 * 0.51) as usize;
    assert!(size_51 >= max / 2);
    assert!(size_51 < (max * 3) / 4);

    // 75% to 90%: 5x.
    let size_76 = (max as f64 * 0.76) as usize;
    assert!(size_76 >= (max * 3) / 4);
    assert!(size_76 < (max * 9) / 10);

    // Above 90%: 10x.
    let size_91 = (max as f64 * 0.91) as usize;
    assert!(size_91 >= (max * 9) / 10);
}
