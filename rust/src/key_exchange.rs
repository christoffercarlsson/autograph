use crate::clib::{
    autograph_key_exchange_signature, autograph_key_exchange_transcript,
    autograph_key_exchange_verify,
};
use crate::session::{
    create_decrypt, create_encrypt, create_sign_data, create_sign_identity, create_verify_data,
    create_verify_identity,
};
use crate::types::{
    Bytes, KeyExchange, KeyExchangeFunction, KeyExchangeResult, KeyExchangeVerificationFunction,
    KeyExchangeVerificationResult, KeyPair, Session, SignFunction,
};
use crate::utils::{
    create_handshake_bytes, create_secret_key_bytes, create_transcript_bytes, SIGNATURE_SIZE,
};
use alloc::boxed::Box;

pub fn create_key_exchange<'a>(
    is_initiator: bool,
    sign: &'a SignFunction,
    identity_public_key: &'a Bytes,
) -> KeyExchangeFunction<'a> {
    Box::new(
        move |ephemeral_key_pair: &mut KeyPair,
              their_identity_key: &'a Bytes,
              their_ephemeral_key: &Bytes| {
            let mut handshake = create_handshake_bytes();
            let mut transcript = create_transcript_bytes();
            let mut our_secret_key = create_secret_key_bytes();
            let mut their_secret_key = create_secret_key_bytes();
            let transcript_success = unsafe {
                autograph_key_exchange_transcript(
                    transcript.as_mut_ptr(),
                    if is_initiator { 1 } else { 0 },
                    identity_public_key.as_ptr(),
                    ephemeral_key_pair.public_key.as_ptr(),
                    their_identity_key.as_ptr(),
                    their_ephemeral_key.as_ptr(),
                )
            } == 0;
            let sign_result = sign(&transcript);
            let key_exchange_success = unsafe {
                autograph_key_exchange_signature(
                    handshake.as_mut_ptr(),
                    our_secret_key.as_mut_ptr(),
                    their_secret_key.as_mut_ptr(),
                    if is_initiator { 1 } else { 0 },
                    sign_result.signature.as_ptr(),
                    ephemeral_key_pair.private_key.as_mut_ptr(),
                    their_ephemeral_key.as_ptr(),
                )
            } == 0;
            let verify = create_key_exchange_verification(
                sign,
                their_identity_key,
                transcript,
                our_secret_key,
                their_secret_key,
            );
            KeyExchangeResult {
                success: transcript_success
                    && sign_result.success
                    && sign_result.signature.len() == SIGNATURE_SIZE
                    && key_exchange_success,
                key_exchange: KeyExchange { handshake, verify },
            }
        },
    )
}

fn create_key_exchange_verification<'a>(
    sign: &'a SignFunction,
    their_public_key: &'a Bytes,
    transcript: Bytes,
    our_secret_key: Bytes,
    their_secret_key: Bytes,
) -> KeyExchangeVerificationFunction<'a> {
    Box::new(move |their_ciphertext: &'a Bytes| {
        let success = unsafe {
            autograph_key_exchange_verify(
                transcript.as_ptr(),
                their_public_key.as_ptr(),
                their_secret_key.as_ptr(),
                their_ciphertext.as_ptr(),
            )
        } == 0;
        let session = Session {
            decrypt: create_decrypt(their_secret_key),
            encrypt: create_encrypt(our_secret_key),
            sign_data: create_sign_data(&sign, &their_public_key),
            sign_identity: create_sign_identity(&sign, &their_public_key),
            verify_data: create_verify_data(&their_public_key),
            verify_identity: create_verify_identity(&their_public_key),
        };
        KeyExchangeVerificationResult { success, session }
    })
}
