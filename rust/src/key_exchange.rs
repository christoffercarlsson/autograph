use crate::{
    cert::{certify, verify},
    error::Error,
    key_pair::{get_identity_public_key, get_session_public_key},
    message::create_secret_key,
    primitives::{AEADPrimitive, DiffieHellmanPrimitive, KeyDerivationPrimitive, SigningPrimitive},
};
use alloc::{vec, vec::Vec};

pub fn create_transcript<P: SigningPrimitive + DiffieHellmanPrimitive>() -> Vec<u8> {
    let size = P::IDENTITY_PUBLIC_KEY_SIZE * 2 + P::SESSION_PUBLIC_KEY_SIZE * 2;
    vec![0; size]
}

fn create_shared_secret<P: DiffieHellmanPrimitive>() -> Vec<u8> {
    vec![0; P::SHARED_SECRET_SIZE]
}

fn derive_key<P: KeyDerivationPrimitive + AEADPrimitive>(
    shared_secret: &[u8],
    transcript: &[u8],
    initiator: bool,
) -> Result<Vec<u8>, Error> {
    let mut key = create_secret_key::<P>();
    let mut info = vec![if initiator { 1 } else { 0 }; 1];
    info.extend_from_slice(transcript);
    let success = P::kdf(&mut key, shared_secret, &info);
    if success {
        Ok(key)
    } else {
        Err(Error::KeyExchange)
    }
}

fn derive_secret_keys<P: DiffieHellmanPrimitive + KeyDerivationPrimitive + AEADPrimitive>(
    is_initiator: bool,
    transcript: &[u8],
    our_session_key_pair: &[u8],
    their_session_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut shared_secret = create_shared_secret::<P>();
    if !P::diffie_hellman(&mut shared_secret, our_session_key_pair, their_session_key) {
        return Err(Error::KeyExchange);
    }
    let a = derive_key::<P>(&shared_secret, transcript, true)?;
    let b = derive_key::<P>(&shared_secret, transcript, false)?;
    if is_initiator {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

fn calculate_transcript<P: SigningPrimitive + DiffieHellmanPrimitive>(
    is_initiator: bool,
    our_identity_key_pair: &[u8],
    our_session_key_pair: &[u8],
    their_identity_key: &[u8],
    their_session_key: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::new();
    let our_identity_key = get_identity_public_key::<P>(our_identity_key_pair);
    let our_session_key = get_session_public_key::<P>(our_session_key_pair);
    if is_initiator {
        transcript.extend_from_slice(&our_identity_key);
        transcript.extend_from_slice(&our_session_key);
        transcript.extend_from_slice(their_identity_key);
        transcript.extend_from_slice(their_session_key);
    } else {
        transcript.extend_from_slice(their_identity_key);
        transcript.extend_from_slice(their_session_key);
        transcript.extend_from_slice(&our_identity_key);
        transcript.extend_from_slice(&our_session_key);
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
    let transcript = calculate_transcript::<P>(
        is_initiator,
        our_identity_key_pair,
        our_session_key_pair,
        their_identity_key,
        their_session_key,
    );
    let signature = certify::<P>(our_identity_key_pair, their_identity_key, Some(&transcript))?;
    let (sending_key, receiving_key) = derive_secret_keys::<P>(
        is_initiator,
        &transcript,
        our_session_key_pair,
        their_session_key,
    )?;
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
