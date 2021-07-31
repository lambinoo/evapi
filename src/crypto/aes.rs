use std::{
    fs::File,
    io::{Read, Write},
};

use aes::Aes256;
use block_modes::{block_padding, BlockMode, BlockModeError, Cbc};
use uuid::Uuid;

const DEFAULT_AES_KEY: &str = "u7x!A%C*F-JaNdRgUkXp2s5v8y/B?E(G";
const DEFAULT_IV: &str = "jXn2r5u8x/A?D(G-";

type Aes256Cbc = Cbc<Aes256, block_padding::Pkcs7>;

pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_var(
        obfstr::obfstr!(&DEFAULT_AES_KEY).as_bytes(),
        obfstr::obfstr!(&DEFAULT_IV).as_bytes(),
    )
    .unwrap();
    cipher.encrypt_vec(plaintext)
}

pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, BlockModeError> {
    let cipher = Aes256Cbc::new_var(
        obfstr::obfstr!(&DEFAULT_AES_KEY).as_bytes(),
        obfstr::obfstr!(&DEFAULT_IV).as_bytes(),
    )
    .unwrap();
    cipher.decrypt_vec(ciphertext)
}
