use crate::{
    cert::{certify, verify},
    error::Error,
    key_pair::{get_identity_public_key, get_session_public_key},
    message::create_secret_key,
    primitives::{AEADPrimitive, DiffieHellmanPrimitive, KeyDerivationPrimitive, SigningPrimitive},
};
use alloc::{vec, vec::Vec};

pub fn create_transcript<P: DiffieHellmanPrimitive>() -> Vec<u8> {
    let size = P::SESSION_PUBLIC_KEY_SIZE * 2;
    vec![0; size]
}

fn create_shared_secret<P: DiffieHellmanPrimitive>() -> Vec<u8> {
    vec![0; P::SHARED_SECRET_SIZE]
}

fn create_okm<P: AEADPrimitive>() -> Vec<u8> {
    let size = P::SECRET_KEY_SIZE * 2;
    vec![0; size]
}

fn calculate_secret_keys<P: AEADPrimitive>(is_initiator: bool, okm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut sending_key = create_secret_key::<P>();
    let mut receiving_key = create_secret_key::<P>();
    if is_initiator {
        sending_key.copy_from_slice(&okm[..P::SECRET_KEY_SIZE]);
        receiving_key.copy_from_slice(&okm[P::SECRET_KEY_SIZE..]);
    } else {
        sending_key.copy_from_slice(&okm[P::SECRET_KEY_SIZE..]);
        receiving_key.copy_from_slice(&okm[..P::SECRET_KEY_SIZE]);
    }
    (sending_key, receiving_key)
}

fn derive_secret_keys<P: DiffieHellmanPrimitive + KeyDerivationPrimitive + AEADPrimitive>(
    is_initiator: bool,
    our_session_key_pair: &[u8],
    their_session_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut shared_secret = create_shared_secret::<P>();
    let mut okm = create_okm::<P>();
    let dh_success = P::diffie_hellman(&mut shared_secret, our_session_key_pair, their_session_key);
    let kdf_success = P::kdf(&mut okm, &shared_secret);
    let (sending_key, receiving_key) = calculate_secret_keys::<P>(is_initiator, &okm);
    if dh_success && kdf_success {
        Ok((sending_key, receiving_key))
    } else {
        Err(Error::KeyExchange)
    }
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

type Transcript = Vec<u8>;
type Signature = Vec<u8>;
type SecretKey = Vec<u8>;

pub fn key_exchange<
    P: SigningPrimitive + DiffieHellmanPrimitive + KeyDerivationPrimitive + AEADPrimitive,
>(
    is_initiator: bool,
    our_identity_key_pair: &[u8],
    our_session_key_pair: &[u8],
    their_identity_key: &[u8],
    their_session_key: &[u8],
) -> Result<(Transcript, Signature, SecretKey, SecretKey), Error> {
    let transcript =
        calculate_transcript::<P>(is_initiator, our_session_key_pair, their_session_key);
    let signature = certify::<P>(our_identity_key_pair, their_identity_key, Some(&transcript))?;
    let (sending_key, receiving_key) =
        derive_secret_keys::<P>(is_initiator, our_session_key_pair, their_session_key)?;
    Ok((transcript, signature, sending_key, receiving_key))
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
