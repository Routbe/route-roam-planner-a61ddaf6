//! 2048-bit class-group Wesolowski VDF run on the public, seed-derived discriminant
//! D = -p (p prime, p = 3 mod 4, so D = 1 mod 4: fundamental, no trusted setup).
//! Integers are fixed-size stack limbs (no heap, no memory.grow) and wiped on drop.
use rout_zk::vdf_cg::{evaluate, verify, PROOF_LEN, P};

#[test]
fn discriminant_is_fundamental() {
    // p = 3 mod 4  <=>  D = -p = 1 mod 4; top bit set => 2048 bits.
    assert_eq!(P[0] & 3, 3);
    assert_eq!(P[31] >> 63, 1);
}

#[test]
fn vdf_2048_round_trip_and_tamper() {
    let mut proof = [0u8; PROOF_LEN];
    evaluate(b"ledger-root", 32, &mut proof).unwrap();
    verify(b"ledger-root", 32, &proof).unwrap();
    assert!(verify(b"ledger-root", 33, &proof).is_err());
    assert!(verify(b"ledger-rooT", 32, &proof).is_err());
    let mut bad = proof;
    bad[PROOF_LEN - 1] ^= 1;
    assert!(verify(b"ledger-root", 32, &bad).is_err());
}
