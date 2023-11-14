use alloc::boxed::Box;

use crate::channel::Channel;
use crate::clib::{
    autograph_key_exchange_signature, autograph_key_exchange_transcript,
    autograph_key_exchange_verify,
};
use crate::types::{
    AutographError, Bytes, KeyExchangeResult, KeyExchangeVerificationFunction, KeyPair,
    SignFunction,
};
use crate::utils::{create_handshake_bytes, create_secret_key_bytes, create_transcript_bytes};

fn create_key_exchange_verification<'a>(
    sign: &'a SignFunction,
    their_identity_key: &'a Bytes,
    transcript: Bytes,
    our_secret_key: Bytes,
    their_secret_key: Bytes,
) -> KeyExchangeVerificationFunction<'a> {
    Box::new(move |their_handshake: Bytes| {
        let success = unsafe {
            autograph_key_exchange_verify(
                transcript.as_ptr(),
                their_identity_key.as_ptr(),
                their_secret_key.as_ptr(),
                their_handshake.as_ptr(),
            )
        } == 0;
        if success {
            Ok(Channel::new(
                sign,
                their_identity_key,
                our_secret_key,
                their_secret_key,
            ))
        } else {
            Err(AutographError::KeyExchangeVerificationError)
        }
    })
}

pub fn perform_key_exchange<'a>(
    sign: &'a SignFunction,
    our_identity_key: &'a Bytes,
    is_initiator: bool,
    mut our_ephemeral_key_pair: KeyPair,
    their_identity_key: &'a Bytes,
    their_ephemeral_key: Bytes,
) -> KeyExchangeResult<'a> {
    let mut handshake = create_handshake_bytes();
    let mut transcript = create_transcript_bytes();
    let mut our_secret_key = create_secret_key_bytes();
    let mut their_secret_key = create_secret_key_bytes();
    let transcript_success = unsafe {
        autograph_key_exchange_transcript(
            transcript.as_mut_ptr(),
            if is_initiator { 1 } else { 0 },
            our_identity_key.as_ptr(),
            our_ephemeral_key_pair.public_key.as_ptr(),
            their_identity_key.as_ptr(),
            their_ephemeral_key.as_ptr(),
        )
    } == 0;
    if !transcript_success {
        return Err(AutographError::KeyExchangeError);
    }
    let signature = sign(&transcript)?;
    let key_exchange_success = unsafe {
        autograph_key_exchange_signature(
            handshake.as_mut_ptr(),
            our_secret_key.as_mut_ptr(),
            their_secret_key.as_mut_ptr(),
            if is_initiator { 1 } else { 0 },
            signature.as_ptr(),
            our_ephemeral_key_pair.private_key.as_mut_ptr(),
            their_ephemeral_key.as_ptr(),
        )
    } == 0;
    if key_exchange_success {
        Ok((
            handshake,
            create_key_exchange_verification(
                sign,
                their_identity_key,
                transcript,
                our_secret_key,
                their_secret_key,
            ),
        ))
    } else {
        Err(AutographError::KeyExchangeError)
    }
}
