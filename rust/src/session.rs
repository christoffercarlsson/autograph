use crate::clib::{
    autograph_decrypt, autograph_encrypt, autograph_subject, autograph_verify_data,
    autograph_verify_identity,
};
use crate::types::{
    Bytes, DecryptFunction, DecryptionResult, DecryptionState, EncryptFunction, EncryptionResult,
    EncryptionState, SignDataFunction, SignFunction, SignIdentityFunction, VerifyDataFunction,
    VerifyIdentityFunction,
};
use crate::utils::{
    create_ciphertext_bytes, create_plaintext_bytes, create_subject_bytes, PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
};
use alloc::boxed::Box;

pub fn create_decrypt<'a>(their_secret_key: Bytes) -> DecryptFunction<'a> {
    let mut state = DecryptionState::new(their_secret_key);
    Box::new(move |message: &Bytes| {
        let mut data = create_plaintext_bytes(message.len());
        let success = unsafe {
            autograph_decrypt(
                data.as_mut_ptr(),
                state.plaintext_size.as_mut_ptr(),
                state.message_index.as_mut_ptr(),
                state.decrypt_index.as_mut_ptr(),
                state.skipped_keys.as_mut_ptr(),
                state.secret_key.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u32,
            )
        } == 0;
        if success {
            state.resize_data(&mut data);
        }
        DecryptionResult {
            success,
            index: state.read_message_index(),
            data,
        }
    })
}

pub fn create_encrypt<'a>(our_secret_key: Bytes) -> EncryptFunction<'a> {
    let mut state = EncryptionState::new(our_secret_key);
    Box::new(move |plaintext: &Bytes| {
        let mut ciphertext = create_ciphertext_bytes(plaintext.len());
        let success = unsafe {
            autograph_encrypt(
                ciphertext.as_mut_ptr(),
                state.message_index.as_mut_ptr(),
                state.secret_key.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len() as u32,
            )
        } == 0;
        EncryptionResult {
            success,
            index: state.read_message_index(),
            message: ciphertext,
        }
    })
}

pub fn create_sign_data<'a>(
    sign: &'a SignFunction,
    their_public_key: &'a Bytes,
) -> SignDataFunction<'a> {
    Box::new(|data: &Bytes| {
        let mut subject = create_subject_bytes(data.len());
        unsafe {
            autograph_subject(
                subject.as_mut_ptr(),
                their_public_key.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
            );
        }
        sign(&subject)
    })
}

pub fn create_sign_identity<'a>(
    sign: &'a SignFunction,
    their_public_key: &'a Bytes,
) -> SignIdentityFunction<'a> {
    Box::new(|| sign(their_public_key))
}

fn count_certificates(certificates: &Bytes) -> u32 {
    (certificates.len() / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)) as u32
}

pub fn create_verify_data(their_public_key: &Bytes) -> VerifyDataFunction {
    Box::new(|certificates: &Bytes, data: &Bytes| unsafe {
        autograph_verify_data(
            their_public_key.as_ptr(),
            certificates.as_ptr(),
            count_certificates(certificates),
            data.as_ptr(),
            data.len() as u32,
        ) == 0
    })
}

pub fn create_verify_identity(their_public_key: &Bytes) -> VerifyIdentityFunction {
    Box::new(|certificates: &Bytes| unsafe {
        autograph_verify_identity(
            their_public_key.as_ptr(),
            certificates.as_ptr(),
            count_certificates(certificates),
        ) == 0
    })
}
