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
use std::io::Write;

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

    // Output the bit vectors making up matrix M
    // format should be:
    // b_0(m_0) b_1(m_0) ... b_255(m_0)
    // b_0(m_1) b_1(m_1) ... b_255(m_1)
    // ...

    let mut file = std::fs::File::create("leaked_message_hashes.txt").expect("create failed");

    for msg in ms.iter() {
        let mut bits = hash_to_bits(blake2s_simd::blake2s(msg)).clone();
        let str = bits_to_string(bits);
        file.write_all(str.as_bytes()).expect("write failed");
        file.write_all("\n".as_bytes()).expect("write failed");
    }

    println!("leaked message hashes written to file");

    let mut username_file = std::fs::File::create("username_hash.txt").expect("create failed");
    let username_bits = hash_to_bits(blake2s_simd::blake2s(username.as_bytes()));
    let username_str = bits_to_string(username_bits);
    username_file.write_all(username_str.as_bytes()).expect("write failed");

    println!("username hash written to file");



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

#[test]
fn test_bits_to_string() {
    let test_input1 = vec![false, false, false, true];
    let test_output1 = bits_to_string(test_input1);
    assert_eq!(test_output1, "0001");

    let test_input2 = vec![true, false, true, true];
    let test_output2 = bits_to_string(test_input2);
    assert_eq!(test_output2, "1011");

    let test_input3 = vec![false, false, false, false];
    let test_output3 = bits_to_string(test_input3);
    assert_eq!(test_output3, "0000");
}

fn bits_to_string(bits: Vec<bool>) -> String {
    let mut string = String::new();
    for bit in bits {
        if bit {
            string.push('1');
        } else {
            string.push('0');
        }
    }
    string
}