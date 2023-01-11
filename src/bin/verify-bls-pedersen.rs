use blake2s_simd::Hash;
use bls_pedersen::bls::verify;
use bls_pedersen::data::puzzle_data;
use bls_pedersen::PUZZLE_DESCRIPTION;
use prompt::{puzzle, welcome};
use bls_pedersen::hash::hash_to_curve;
extern crate nalgebra as na;
use na::base::{DMatrix, Matrix2x4};
use na::{Matrix, Vector2};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let (pk, ms, sigs) = puzzle_data();
    // for (m, sig) in ms.iter().zip(sigs.iter()) {
    //     verify(pk, m, *sig);
    // }

    /* Your solution here! */
    /*
      let sig = ...;
      let m = your username;
      verify(pk, m, sig);
    */

    // for m in ms.iter() {
    //     for i in 0..m.len() {
    //         println!("{:#010b}", m[i]);
    //     }
    //     println!();
    // }

    // set username
    let username = "poliwop";
    // hash username
    let (_, h) = hash_to_curve(username.as_bytes());
    println!("h: {:?}", h);
    // compute hashed username as a linear combination of hashes of the leaked usernames
    // using same coefficients, compute signature for my username


    let mut bit_vec: Vec<bool> = vec![];

    for msg in ms.iter() {
        let mut bits = hash_to_bits(blake2s_simd::blake2s(msg)).clone();
        bit_vec.append(&mut bits);
    }

    // Output the bit vectors making up matrix M
    // format should be:
    // b_0(m_0) b_1(m_0) ... b_255(m_0)
    // b_0(m_1) b_1(m_1) ... b_255(m_1)
    // ...


    // Output the vector c
    // format should be:
    // c_0 c_1 ... c_255

    // Solve Mx = c elsewhere, i.e. calculate x = c * M^-1 elsewhere
    // Note that these computations must be done in F_r

    // Import x


}

fn byte_to_bits(byte: u8) -> Vec<bool> {
    let mut bits = vec![];
    for i in 0..8 {
        bits.push(((byte >> (7-i)) & 1) != 0);
    }
    bits
}

#[test]
fn test_byte_to_bits() {
    assert_eq!(byte_to_bits(0_u8), vec![false, false, false, false, false, false, false, false]);
    assert_eq!(byte_to_bits(1_u8), vec![false, false, false, false, false, false, false, true]);
    assert_eq!(byte_to_bits(2_u8), vec![false, false, false, false, false, false, true, false]);
    assert_eq!(byte_to_bits(3_u8), vec![false, false, false, false, false, false, true, true]);
    assert_eq!(byte_to_bits(4_u8), vec![false, false, false, false, false, true, false, false]);
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = vec![];
    for byte in bytes {
        bits.extend(byte_to_bits(*byte));
    }
    bits
}

#[test]
fn test_bytes_to_bits() {
    assert_eq!(bytes_to_bits(&[1_u8, 3_u8]),
               vec![false, false, false, false, false, false, false, true,
                    false, false, false, false, false, false, true, true]);
}


fn hash_to_bits(hash: Hash) -> Vec<bool> {
    bytes_to_bits(hash.as_bytes())
}

// #[test]
// fn test_hash_to_bits(msg: &[u8]) {
//     println!("{:?}", hash_to_bits(blake2s_simd::blake2s(msg)));
// }