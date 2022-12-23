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


    fn byte_to_bits(byte: u8) -> Vec<bool> {
        let mut bits = vec![];
        for i in 0..8 {
            bits.push(((byte >> (7-i)) & 1) != 0);
        }
        bits
    }

    // let bytes = [0_u8, 1_u8, 2_u8, 3_u8, 4_u8];
    // for byte in bytes.iter() {
    //     println!("{:?}", byte_to_bits(*byte));
    // }

    fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
        let mut bits = vec![];
        for byte in bytes {
            bits.extend(byte_to_bits(*byte));
        }
        bits
    }

    // let bytes = [1_u8, 4_u8];
    // println!("{:?}", bytes_to_bits(&bytes));

    fn hash_to_bits(hash: Hash) -> Vec<bool> {
        bytes_to_bits(hash.as_bytes())
    }

    // for msg in ms.iter() {
    //     println!("{:?}", hash_to_bits(blake2s_simd::blake2s(msg)));
    // }

    let mut bit_vec: Vec<bool> = vec![];

    for msg in ms.iter() {
        let mut bits = hash_to_bits(blake2s_simd::blake2s(msg)).clone();
        bit_vec.append(&mut bits);
    }

    let mut dm = DMatrix::from_iterator(256, 256, bit_vec);


    // println!("{:?}", dm);


    // let mut m = Matrix2x4::new(true, true, false, false,
    //                        false, true, true, false);

    fn xor_rows(mut m: DMatrix<bool>, i: usize, j: usize) -> DMatrix<bool> {
        let mut row1 = m.row(i).clone_owned();
        let mut row2 = m.row(j).clone_owned();
        for k in 0..row1.len() {
            m[(j,k)] = row1[k] ^ row2[k];
        }
        m
    }

    //calculate inverse of matrix
    fn invert_boolean_matrix(mut dm: DMatrix<bool>) -> DMatrix<bool> {
        let size = dm.nrows();
        let mut im = DMatrix::<bool>::from_element(size, size, false);
        for i in 0..size {
            im[(i, i)] = true;
        }

        for col_idx in 0..dm.ncols() {
            // find first row with nonzero entry in column starting at row col_idx, swap with row col_idx
            for row_idx in col_idx..dm.nrows() {
                if dm[(row_idx, col_idx)] {
                    if row_idx != col_idx {
                        dm.swap_rows(col_idx, row_idx);
                        im.swap_rows(col_idx, row_idx);
                    }
                    break;
                }
            }
            // for each row other than col_idx, if entry in col_idx is nonzero, xor with row col_idx
            for row_idx in 0..dm.nrows() {
                if row_idx != col_idx {
                    if dm[(row_idx, col_idx)] {
                        dm = xor_rows(dm, col_idx, row_idx);
                        im = xor_rows(im, col_idx, row_idx);
                    }
                }
            }
        }
        im
    }

    fn print_type_of<T>(_: &T) {
        println!("{}", std::any::type_name::<T>())
    }

    fn print_dmatrix(dm: DMatrix<bool>) {
        for i in 0..dm.nrows() {
            for j in 0..dm.ncols() {
                print!("{}, ", dm[(i,j)]);
            }
            println!();
        }
    }

    // // let dm_test = DMatrix::from_columns(&[vec![true, false], vec![false, true]]);
    // let dm_test = DMatrix::from_iterator(3, 3, [false, true, true,
    //                                                                         true, true, false,
    //                                                                         false, true, false]);
    // let dm_test2 = dm_test.transpose();
    // println!("{:?}", dm_test2);
    //
    //
    // print_dmatrix(dm_test2.clone());
    // let im = invert_boolean_matrix(dm_test2);
    // print_dmatrix(im.clone());

    let im = invert_boolean_matrix(dm);
    print_dmatrix(im.clone());


    //multiply matrix by vector
    // let vec1 = hash_to_bits(blake2s_simd::blake2s(&ms[0]));
    let vec1 = hash_to_bits(blake2s_simd::blake2s(username.as_bytes()));
    let mut vec2 = vec![];
    for i in 0..256 {
        let mut sum = false;
        for j in 0..256 {
            sum = sum ^ (im[(i,j)] & vec1[j]);
        }
        vec2.push(sum);
    }

    let mut vec3 = vec![];

    for i in 0..32 {
        let mut byte = 0_u8;
        for j in 0..8 {
            byte = byte << 1;
            byte = byte | (vec2[i*8 + j] as u8);
        }
        vec3.push(byte);
    }

    // dot product of signatures and vec3, at bit level


    println!("{:?}", vec3);
    // let mut vec4 = vec![];
    // for i in 0..vec3.len() {
    //     vec4.push(vec3[i] | sigs[0][i]);
    // }


    // Gauss-Jordan elimination





    // need to find a username such that its hashed value is a linear combination of hashed values of the leaked messages
    // do the hashed values of leaked messages form a spanning set?

    // let sig0 = sigs[0];
    // let sig1 = sigs[1];
    // let m0 = ms[0].clone();
    // let m1 = ms[1].clone();
    // let (_, hm0) = hash_to_curve(&m0);
    // let (_, hm1) = hash_to_curve(&m1);
    //
    // let mut m01: Vec<u8>;
    // let m01 = m0.clone() + &m1;
    // for i in 0..m0.len() {
    //     println!("m0: {}", m0[i]);
    // }
    // for i in 0..m1.len() {
    //     println!("m0: {}", m1[i]);
    // }
    // println!("m01: {}", m01);

}
