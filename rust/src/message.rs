use crate::{error::Error, primitives::AEADPrimitive};
use alloc::{vec, vec::Vec};
use rand_core::{CryptoRng, RngCore};

const PADDING_BLOCK_SIZE: usize = 16;
const PADDING_BYTE: u8 = 128;
const DEFAULT_SKIPPED_INDEXES_COUNT: u16 = 128;

pub fn create_secret_key<P: AEADPrimitive>() -> Vec<u8> {
    vec![0; P::SECRET_KEY_SIZE]
}

pub fn create_nonce<P: AEADPrimitive>() -> Vec<u8> {
    vec![0; P::NONCE_SIZE]
}

pub fn create_skipped_indexes(count: Option<u16>) -> Vec<u8> {
    let size = count.unwrap_or(DEFAULT_SKIPPED_INDEXES_COUNT) * 4;
    vec![0; size as usize]
}

pub fn generate_secret_key<T: RngCore + CryptoRng, P: AEADPrimitive>(
    csprng: T,
) -> Result<Vec<u8>, Error> {
    let mut secret_key = create_secret_key::<P>();
    let success = P::generate_key(csprng, &mut secret_key);
    if !success {
        return Err(Error::KeyGeneration);
    }
    Ok(secret_key)
}

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

pub fn get_uint32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub fn set_uint32(bytes: &mut [u8], offset: usize, number: u32) {
    bytes[offset..offset + 4].copy_from_slice(number.to_be_bytes().as_slice());
}

fn get_index<P: AEADPrimitive>(nonce: &[u8]) -> u32 {
    get_uint32(nonce, P::NONCE_SIZE - 4)
}

fn set_index<P: AEADPrimitive>(nonce: &mut [u8], index: u32) {
    set_uint32(nonce, P::NONCE_SIZE - 4, index)
}

fn increment_nonce<P: AEADPrimitive>(nonce: &mut [u8], error: Error) -> Result<(), Error> {
    let index = get_index::<P>(nonce);
    if index == u32::MAX {
        return Err(error);
    }
    set_index::<P>(nonce, index + 1);
    Ok(())
}

fn create_ciphertext<P: AEADPrimitive>(plaintext: &[u8]) -> Vec<u8> {
    vec![0; calculate_padded_size(plaintext) + P::TAG_SIZE]
}

fn create_plaintext<P: AEADPrimitive>(ciphertext: &[u8]) -> Vec<u8> {
    vec![0; ciphertext.len() - P::TAG_SIZE]
}

pub fn encrypt<P: AEADPrimitive>(
    key: &[u8],
    nonce: &mut [u8],
    plaintext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    increment_nonce::<P>(nonce, Error::Encryption)?;
    let mut ciphertext = create_ciphertext::<P>(plaintext);
    let padded = pad(plaintext);
    if P::encrypt(&mut ciphertext, key, nonce, &padded) {
        Ok((get_index::<P>(nonce), ciphertext))
    } else {
        Err(Error::Encryption)
    }
}

fn decrypt_ciphertext<P: AEADPrimitive>(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    let mut plaintext = create_plaintext::<P>(ciphertext);
    if P::decrypt(&mut plaintext, key, nonce, ciphertext) {
        unpad(&mut plaintext)?;
        Ok((get_index::<P>(nonce), plaintext))
    } else {
        Err(Error::Decryption)
    }
}

fn decrypt_skipped<P: AEADPrimitive>(
    key: &[u8],
    skipped_indexes: &mut [u8],
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    let mut nonce = create_nonce::<P>();
    let mut index;
    for offset in (0..skipped_indexes.len()).step_by(4) {
        index = get_uint32(skipped_indexes, offset);
        if index == 0 {
            continue; // TODO: Order skipped indexes so that we can break as soon as
                      // possible
        }
        set_index::<P>(&mut nonce, index);
        let result = decrypt_ciphertext::<P>(key, &nonce, ciphertext);
        if result.is_ok() {
            set_uint32(skipped_indexes, offset, 0);
            return result;
        }
    }
    Err(Error::Decryption)
}

fn skip_index<P: AEADPrimitive>(skipped_indexes: &mut [u8], nonce: &[u8]) -> Result<(), Error> {
    let index = get_index::<P>(nonce);
    for i in (0..skipped_indexes.len()).step_by(4) {
        if get_uint32(skipped_indexes, i) == 0 {
            set_uint32(skipped_indexes, i, index);
            return Ok(());
        }
    }
    Err(Error::Decryption)
}

pub fn decrypt<P: AEADPrimitive>(
    key: &[u8],
    nonce: &mut [u8],
    skipped_indexes: &mut [u8],
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    let mut result = decrypt_skipped::<P>(key, skipped_indexes, ciphertext);
    while result.is_err() {
        increment_nonce::<P>(nonce, Error::Decryption)?;
        result = decrypt_ciphertext::<P>(key, nonce, ciphertext);
        if result.is_err() {
            skip_index::<P>(skipped_indexes, nonce)?;
        }
    }
    result
}
