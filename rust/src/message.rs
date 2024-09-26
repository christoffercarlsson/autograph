use stedy::{
    chacha20poly1305_decrypt, chacha20poly1305_encrypt, increment_nonce, pad, read_nonce,
    read_u64_be, unpad, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, Vec,
    CHACHA20_POLY1305_NONCE_SIZE, CHACHA20_POLY1305_TAG_SIZE,
};

use crate::Error;

const PADDING_BLOCK_SIZE: usize = 16;
const MIN_MESSAGE_SIZE: usize =
    CHACHA20_POLY1305_NONCE_SIZE + PADDING_BLOCK_SIZE + CHACHA20_POLY1305_TAG_SIZE;

fn prepend_nonce(ciphertext: &mut Vec<u8>, nonce: &ChaCha20Poly1305Nonce) -> u64 {
    let ciphertext_size = ciphertext.len();
    ciphertext.resize(ciphertext_size + CHACHA20_POLY1305_NONCE_SIZE, 0);
    ciphertext.copy_within(0..ciphertext_size, CHACHA20_POLY1305_NONCE_SIZE);
    ciphertext[..CHACHA20_POLY1305_NONCE_SIZE].copy_from_slice(nonce);
    read_u64_be(ciphertext, CHACHA20_POLY1305_NONCE_SIZE - size_of::<u64>()).unwrap_or(0)
}

pub fn encrypt(
    key: &ChaCha20Poly1305Key,
    nonce: &mut ChaCha20Poly1305Nonce,
    plaintext: &[u8],
) -> Result<(u64, Vec<u8>), Error> {
    increment_nonce(nonce).or(Err(Error::Encryption))?;
    let mut plaintext = plaintext.to_vec();
    pad(&mut plaintext, PADDING_BLOCK_SIZE);
    let mut message =
        chacha20poly1305_encrypt(key, nonce, &plaintext, None).or(Err(Error::Encryption))?;
    let index = prepend_nonce(&mut message, nonce);
    Ok((index, message))
}

fn parse_message(message: &[u8]) -> Result<(ChaCha20Poly1305Nonce, u64, &[u8]), Error> {
    if message.len() < MIN_MESSAGE_SIZE {
        return Err(Error::Message);
    }
    let nonce: ChaCha20Poly1305Nonce = message[..CHACHA20_POLY1305_NONCE_SIZE]
        .try_into()
        .or(Err(Error::Message))?;
    let index = read_nonce(&nonce).or(Err(Error::Message))?;
    let ciphertext = &message[CHACHA20_POLY1305_NONCE_SIZE..];
    Ok((nonce, index, ciphertext))
}

pub fn decrypt(key: &ChaCha20Poly1305Key, message: &[u8]) -> Result<(u64, Vec<u8>), Error> {
    let (nonce, index, ciphertext) = parse_message(message)?;
    let mut plaintext =
        chacha20poly1305_decrypt(key, &nonce, ciphertext, None).or(Err(Error::Decryption))?;
    unpad(&mut plaintext, PADDING_BLOCK_SIZE).or(Err(Error::Decryption))?;
    Ok((index, plaintext))
}
