use crate::{
    cert::{certify, verify},
    constants::{
        INFO, OKM_SIZE, PUBLIC_KEY_SIZE, SALT_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
        TRANSCRIPT_SIZE,
    },
    error::Error,
    external::{diffie_hellman, hkdf},
    get_public_key,
    types::{KeyPair, Okm, PublicKey, SecretKey, SharedSecret, Signature, Transcript},
};

fn calculate_secret_keys(is_initiator: bool, okm: &Okm) -> (SecretKey, SecretKey) {
    let mut sending_key = [0; SECRET_KEY_SIZE];
    let mut receiving_key = [0; SECRET_KEY_SIZE];
    if is_initiator {
        sending_key.copy_from_slice(&okm[..SECRET_KEY_SIZE]);
        receiving_key.copy_from_slice(&okm[SECRET_KEY_SIZE..]);
    } else {
        sending_key.copy_from_slice(&okm[SECRET_KEY_SIZE..]);
        receiving_key.copy_from_slice(&okm[..SECRET_KEY_SIZE]);
    }
    (sending_key, receiving_key)
}

fn derive_secret_keys(
    is_initiator: bool,
    our_session_key_pair: &KeyPair,
    their_session_key: &PublicKey,
) -> Result<(SecretKey, SecretKey), Error> {
    let mut shared_secret: SharedSecret = [0; SHARED_SECRET_SIZE];
    let mut okm: Okm = [0; OKM_SIZE];
    let dh_success = diffie_hellman(&mut shared_secret, our_session_key_pair, their_session_key);
    let salt = [0; SALT_SIZE];
    let kdf_success = hkdf(&mut okm, &shared_secret, &salt, &INFO);
    let (sending_key, receiving_key) = calculate_secret_keys(is_initiator, &okm);
    if dh_success && kdf_success {
        Ok((sending_key, receiving_key))
    } else {
        Err(Error::KeyExchange)
    }
}

fn calculate_transcript(
    is_initiator: bool,
    our_session_key_pair: &KeyPair,
    their_session_key: &PublicKey,
) -> Transcript {
    let mut transcript = [0; TRANSCRIPT_SIZE];
    let our_session_key = get_public_key(our_session_key_pair);
    if is_initiator {
        transcript[..PUBLIC_KEY_SIZE].copy_from_slice(&our_session_key);
        transcript[PUBLIC_KEY_SIZE..].copy_from_slice(their_session_key);
    } else {
        transcript[..PUBLIC_KEY_SIZE].copy_from_slice(their_session_key);
        transcript[PUBLIC_KEY_SIZE..].copy_from_slice(&our_session_key);
    }
    transcript
}

pub fn key_exchange(
    is_initiator: bool,
    our_identity_key_pair: &KeyPair,
    our_session_key_pair: &KeyPair,
    their_identity_key: &PublicKey,
    their_session_key: &PublicKey,
) -> Result<(Transcript, Signature, SecretKey, SecretKey), Error> {
    let transcript = calculate_transcript(is_initiator, our_session_key_pair, their_session_key);
    let signature = certify(our_identity_key_pair, their_identity_key, Some(&transcript))?;
    let (sending_key, receiving_key) =
        derive_secret_keys(is_initiator, our_session_key_pair, their_session_key)?;
    Ok((transcript, signature, sending_key, receiving_key))
}

pub fn verify_key_exchange(
    transcript: &Transcript,
    our_identity_key_pair: &KeyPair,
    their_identity_key: &PublicKey,
    their_signature: &Signature,
) -> Result<(), Error> {
    let our_identity_key = get_public_key(our_identity_key_pair);
    let verified = verify(
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
