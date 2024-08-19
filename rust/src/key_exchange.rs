use crate::{
    cert::{certify, verify},
    error::Error,
    key_pair::{get_identity_public_key, get_session_public_key},
    message::create_secret_key,
    primitives::{AEADPrimitive, DiffieHellmanPrimitive, KeyDerivationPrimitive, SigningPrimitive},
};
use alloc::{vec, vec::Vec};

fn derive_secret_keys<
    P: SigningPrimitive + DiffieHellmanPrimitive + KeyDerivationPrimitive + AEADPrimitive,
>(
    is_initiator: bool,
    our_identity_key_pair: &[u8],
    our_session_key_pair: &[u8],
    their_identity_key: &[u8],
    their_session_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let our_identity_key = get_identity_public_key::<P>(our_identity_key_pair);
    let mut shared_secret = vec![0; P::SHARED_SECRET_SIZE];
    if !P::diffie_hellman(&mut shared_secret, our_session_key_pair, their_session_key) {
        return Err(Error::KeyExchange);
    }
    let mut a = create_secret_key::<P>();
    let mut b = create_secret_key::<P>();
    if !P::kdf(&mut a, &shared_secret, &our_identity_key) {
        return Err(Error::KeyExchange);
    }
    if !P::kdf(&mut b, &shared_secret, their_identity_key) {
        return Err(Error::KeyExchange);
    }
    if is_initiator {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

pub fn create_transcript<P: DiffieHellmanPrimitive>() -> Vec<u8> {
    vec![0; P::SESSION_PUBLIC_KEY_SIZE * 2]
}

fn calculate_transcript<P: DiffieHellmanPrimitive>(
    is_initiator: bool,
    our_session_key_pair: &[u8],
    their_session_key: &[u8],
) -> Vec<u8> {
    let mut transcript = create_transcript::<P>();
    let our_session_key = get_session_public_key::<P>(our_session_key_pair);
    if is_initiator {
        transcript[..P::SESSION_PUBLIC_KEY_SIZE].copy_from_slice(&our_session_key);
        transcript[P::SESSION_PUBLIC_KEY_SIZE..].copy_from_slice(their_session_key);
    } else {
        transcript[..P::SESSION_PUBLIC_KEY_SIZE].copy_from_slice(their_session_key);
        transcript[P::SESSION_PUBLIC_KEY_SIZE..].copy_from_slice(&our_session_key);
    }
    transcript
}

pub struct KeyExchangeResult {
    pub transcript: Vec<u8>,
    pub signature: Vec<u8>,
    pub sending_key: Vec<u8>,
    pub receiving_key: Vec<u8>,
}

pub fn key_exchange<
    P: SigningPrimitive + DiffieHellmanPrimitive + KeyDerivationPrimitive + AEADPrimitive,
>(
    is_initiator: bool,
    our_identity_key_pair: &[u8],
    our_session_key_pair: &[u8],
    their_identity_key: &[u8],
    their_session_key: &[u8],
) -> Result<KeyExchangeResult, Error> {
    let transcript =
        calculate_transcript::<P>(is_initiator, our_session_key_pair, their_session_key);
    let signature = certify::<P>(our_identity_key_pair, their_identity_key, Some(&transcript))?;
    let (sending_key, receiving_key) = derive_secret_keys::<P>(
        is_initiator,
        our_identity_key_pair,
        our_session_key_pair,
        their_identity_key,
        their_session_key,
    )?;
    Ok(KeyExchangeResult {
        transcript,
        signature,
        sending_key,
        receiving_key,
    })
}

pub fn verify_key_exchange<P: SigningPrimitive>(
    transcript: &[u8],
    our_identity_key_pair: &[u8],
    their_identity_key: &[u8],
    their_signature: &[u8],
) -> Result<(), Error> {
    let our_identity_key = get_identity_public_key::<P>(our_identity_key_pair);
    let verified = verify::<P>(
        &our_identity_key,
        their_identity_key,
        their_signature,
        Some(transcript),
    );
    if !verified {
        Err(Error::KeyExchange)
    } else {
        Ok(())
    }
}
