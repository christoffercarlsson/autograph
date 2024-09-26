use stedy::{
    ed25519_get_public_key, x25519_get_public_key, x25519_key_exchange, zeroize,
    ChaCha20Poly1305Key, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, X25519KeyPair,
    X25519PublicKey, X25519SharedSecret, CHACHA20_POLY1305_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE,
    X25519_PUBLIC_KEY_SIZE,
};

use crate::{certify, kdf::derive_key, verify, Error};

const TRANSCRIPT_SIZE: usize = ED25519_PUBLIC_KEY_SIZE * 2 + X25519_PUBLIC_KEY_SIZE * 2;
const TRANSCRIPT_OFFSET_A: usize = 0;
const TRANSCRIPT_OFFSET_B: usize = TRANSCRIPT_OFFSET_A + ED25519_PUBLIC_KEY_SIZE;
const TRANSCRIPT_OFFSET_C: usize = TRANSCRIPT_OFFSET_B + X25519_PUBLIC_KEY_SIZE;
const TRANSCRIPT_OFFSET_D: usize = TRANSCRIPT_OFFSET_C + ED25519_PUBLIC_KEY_SIZE;

type Transcript = [u8; TRANSCRIPT_SIZE];

fn get_transcript(
    a: &Ed25519PublicKey,
    b: &X25519PublicKey,
    c: &Ed25519PublicKey,
    d: &X25519PublicKey,
) -> Transcript {
    let mut transcript: Transcript = [0; TRANSCRIPT_SIZE];
    transcript[TRANSCRIPT_OFFSET_A..TRANSCRIPT_OFFSET_B].copy_from_slice(a);
    transcript[TRANSCRIPT_OFFSET_B..TRANSCRIPT_OFFSET_C].copy_from_slice(b);
    transcript[TRANSCRIPT_OFFSET_C..TRANSCRIPT_OFFSET_D].copy_from_slice(c);
    transcript[TRANSCRIPT_OFFSET_D..].copy_from_slice(d);
    transcript
}

fn calculate_our_transcript(
    our_identity_key_pair: &Ed25519KeyPair,
    our_session_key_pair: &X25519KeyPair,
    their_identity_key: &Ed25519PublicKey,
    their_session_key: &X25519PublicKey,
) -> Transcript {
    let our_identity_key = ed25519_get_public_key(our_identity_key_pair);
    let our_session_key = x25519_get_public_key(our_session_key_pair);
    get_transcript(
        &our_identity_key,
        &our_session_key,
        their_identity_key,
        their_session_key,
    )
}

fn calculate_their_transcript(
    our_identity_key_pair: &Ed25519KeyPair,
    our_session_key_pair: &X25519KeyPair,
    their_identity_key: &Ed25519PublicKey,
    their_session_key: &X25519PublicKey,
) -> Transcript {
    let our_identity_key = ed25519_get_public_key(our_identity_key_pair);
    let our_session_key = x25519_get_public_key(our_session_key_pair);
    get_transcript(
        their_identity_key,
        their_session_key,
        &our_identity_key,
        &our_session_key,
    )
}

fn derive_secret_key(
    shared_secret: &X25519SharedSecret,
    transcript: &Transcript,
) -> Result<ChaCha20Poly1305Key, Error> {
    let mut key = [0; CHACHA20_POLY1305_KEY_SIZE];
    derive_key(&mut key, shared_secret, Some(transcript))?;
    Ok(key)
}

fn perform_key_exchange(
    our_session_key_pair: &X25519KeyPair,
    their_session_key: &X25519PublicKey,
    our_transcript: &Transcript,
    their_transcript: &Transcript,
) -> Result<(ChaCha20Poly1305Key, ChaCha20Poly1305Key), Error> {
    let mut shared_secret = x25519_key_exchange(our_session_key_pair, their_session_key);
    let sending_key = derive_secret_key(&shared_secret, our_transcript)?;
    let receiving_key = derive_secret_key(&shared_secret, their_transcript)?;
    zeroize(&mut shared_secret);
    Ok((sending_key, receiving_key))
}

pub fn key_exchange(
    our_identity_key_pair: &Ed25519KeyPair,
    our_session_key_pair: &X25519KeyPair,
    their_identity_key: &Ed25519PublicKey,
    their_session_key: &X25519PublicKey,
) -> Result<(Ed25519Signature, ChaCha20Poly1305Key, ChaCha20Poly1305Key), Error> {
    let our_transcript = calculate_our_transcript(
        our_identity_key_pair,
        our_session_key_pair,
        their_identity_key,
        their_session_key,
    );
    let their_transcript = calculate_their_transcript(
        our_identity_key_pair,
        our_session_key_pair,
        their_identity_key,
        their_session_key,
    );
    let signature = certify(
        our_identity_key_pair,
        their_identity_key,
        Some(&their_transcript),
    )
    .or(Err(Error::KeyExchange))?;
    let (sending_key, receiving_key) = perform_key_exchange(
        our_session_key_pair,
        their_session_key,
        &our_transcript,
        &their_transcript,
    )
    .or(Err(Error::KeyExchange))?;
    Ok((signature, sending_key, receiving_key))
}

pub fn verify_key_exchange(
    our_identity_key_pair: &Ed25519KeyPair,
    our_session_key_pair: &X25519KeyPair,
    their_identity_key: &Ed25519PublicKey,
    their_session_key: &X25519PublicKey,
    signature: &Ed25519Signature,
) -> Result<(), Error> {
    let our_identity_key = ed25519_get_public_key(our_identity_key_pair);
    let transcript = calculate_our_transcript(
        our_identity_key_pair,
        our_session_key_pair,
        their_identity_key,
        their_session_key,
    );
    verify(
        &our_identity_key,
        their_identity_key,
        signature,
        Some(&transcript),
    )
}
