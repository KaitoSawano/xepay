// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use xepay::blockchain::{self, Blockchain};

#[test]
fn reward_era_0() {
    let r = Blockchain::calculate_reward(0);
    assert_eq!(r, blockchain::initial_reward());
}

#[test]
fn reward_era_1() {
    // The reward is reduced by 10% per era, so era 1 is 90% of era 0.
    let r = Blockchain::calculate_reward(blockchain::subsidy_halving_interval());
    let expected = blockchain::initial_reward()
        .saturating_mul(blockchain::reward_reduction_numerator())
        / blockchain::reward_reduction_denominator();
    assert_eq!(r, expected);
}

#[test]
fn reward_era_2() {
    // Era 2 is 90% of era 1, which is 81% of era 0.
    let r = Blockchain::calculate_reward(blockchain::subsidy_halving_interval() * 2);
    let era1 = blockchain::initial_reward()
        .saturating_mul(blockchain::reward_reduction_numerator())
        / blockchain::reward_reduction_denominator();
    let expected = era1
        .saturating_mul(blockchain::reward_reduction_numerator())
        / blockchain::reward_reduction_denominator();
    assert_eq!(r, expected);
}

#[test]
fn reward_at_max_eras_is_zero() {
    let height = blockchain::subsidy_halving_interval() * (blockchain::max_eras() as u64);
    let r = Blockchain::calculate_reward(height);
    assert_eq!(r, 0);
}

#[test]
fn reward_beyond_max_eras_is_zero() {
    let height = blockchain::subsidy_halving_interval() * (blockchain::max_eras() as u64 + 1);
    let r = Blockchain::calculate_reward(height);
    assert_eq!(r, 0);
}
