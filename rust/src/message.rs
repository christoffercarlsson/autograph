use alloc::vec;
use alloc::vec::Vec;

use crate::{
    constants::{NONCE_SIZE, PADDING_BLOCK_SIZE, PADDING_BYTE, TAG_SIZE},
    error::Error,
    external::{decrypt as external_decrypt, encrypt as external_encrypt},
    support::{get_uint32, set_uint32},
    types::{Nonce, SecretKey},
};

fn calculate_padded_size(plaintext: &[u8]) -> usize {
    let size = plaintext.len();
    size + PADDING_BLOCK_SIZE - (size % PADDING_BLOCK_SIZE)
}

fn pad(plaintext: &[u8]) -> Vec<u8> {
    let mut padded = plaintext.to_vec();
    padded.resize(calculate_padded_size(plaintext), 0);
    padded[plaintext.len()] = PADDING_BYTE;
    padded
}

fn calculate_unpadded_size(padded: &[u8]) -> usize {
    let size = padded.len();
    if size == 0 || (size % PADDING_BLOCK_SIZE) > 0 {
        return 0;
    }
    for i in (size - PADDING_BLOCK_SIZE..size).rev() {
        let byte = padded[i];
        if byte == PADDING_BYTE {
            return i;
        }
        if byte != 0 {
            return 0;
        }
    }
    0
}

fn unpad(plaintext: &mut Vec<u8>) -> Result<(), Error> {
    let size = calculate_unpadded_size(plaintext);
    if size == 0 {
        return Err(Error::Decryption);
    }
    plaintext.resize(size, 0);
    Ok(())
}

fn get_index(nonce: &Nonce) -> u32 {
    get_uint32(nonce, NONCE_SIZE - 4)
}

fn set_index(nonce: &mut Nonce, index: u32) {
    set_uint32(nonce, NONCE_SIZE - 4, index)
}

fn increment_nonce(nonce: &mut Nonce, error: Error) -> Result<(), Error> {
    let index = get_index(nonce);
    if index == u32::MAX {
        return Err(error);
    }
    set_index(nonce, index + 1);
    Ok(())
}

fn create_ciphertext(plaintext: &[u8]) -> Vec<u8> {
    vec![0; calculate_padded_size(plaintext) + TAG_SIZE]
}

fn create_plaintext(ciphertext: &[u8]) -> Vec<u8> {
    vec![0; ciphertext.len() - TAG_SIZE]
}

pub fn encrypt(
    key: &SecretKey,
    nonce: &mut Nonce,
    plaintext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    increment_nonce(nonce, Error::Encryption)?;
    let mut ciphertext = create_ciphertext(plaintext);
    let padded = pad(plaintext);
    if external_encrypt(&mut ciphertext, key, nonce, &padded) {
        Ok((get_index(nonce), ciphertext))
    } else {
        Err(Error::Encryption)
    }
}

fn decrypt_ciphertext(
    key: &SecretKey,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    let mut plaintext = create_plaintext(ciphertext);
    if external_decrypt(&mut plaintext, key, nonce, ciphertext) {
        unpad(&mut plaintext)?;
        Ok((get_index(nonce), plaintext))
    } else {
        Err(Error::Decryption)
    }
}

fn decrypt_skipped(
    key: &SecretKey,
    skipped_indexes: &mut [u32],
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    let mut nonce = [0; NONCE_SIZE];
    for i in skipped_indexes.iter_mut() {
        if *i == 0 {
            continue;
        }
        set_index(&mut nonce, *i);
        let result = decrypt_ciphertext(key, &nonce, ciphertext);
        if result.is_ok() {
            *i = 0;
            return result;
        }
    }
    Err(Error::Decryption)
}

fn skip_index(skipped_indexes: &mut [u32], nonce: &Nonce) -> Result<(), Error> {
    let index = get_index(nonce);
    for i in skipped_indexes.iter_mut() {
        if *i == 0 {
            *i = index;
            return Ok(());
        }
    }
    Err(Error::Decryption)
}

pub fn decrypt(
    key: &SecretKey,
    nonce: &mut Nonce,
    skipped_indexes: &mut [u32],
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    let mut result = decrypt_skipped(key, skipped_indexes, ciphertext);
    while result.is_err() {
        increment_nonce(nonce, Error::Decryption)?;
        result = decrypt_ciphertext(key, nonce, ciphertext);
        if result.is_err() {
            skip_index(skipped_indexes, nonce)?;
        }
    }
    result
}
