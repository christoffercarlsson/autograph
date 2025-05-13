#![no_std]

extern crate ed25519_dalek;
extern crate stedy;
extern crate x25519_dalek;

mod primitive;
mod protocol;

use crate::primitive::{Cipher, DiffieHellman, Hasher, Kdf};
pub use crate::{primitive::Signer, protocol::*};

pub fn authenticate(
    signer: &Signer,
    our_id: &[u8],
    their_identity_key: &[u8; 32],
    their_id: &[u8],
) -> Result<[u8; 64], Error> {
    auth::authenticate::<Hasher, Signer>(signer, our_id, their_identity_key, their_id)
}

pub fn key_pair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    session::key_pair::<DiffieHellman>(seed)
}

pub fn key_exchange(
    signer: &Signer,
    our_private_key: &[u8; 32],
    our_public_key: &[u8; 32],
    their_identity_key: &[u8; 32],
    their_public_key: &[u8; 32],
    pre_shared_secret: Option<&[u8; 32]>,
) -> Result<([u8; 32], [u8; 64]), Error> {
    session::key_exchange::<DiffieHellman, Hasher, Kdf, Signer>(
        signer,
        our_private_key,
        our_public_key,
        their_identity_key,
        their_public_key,
        pre_shared_secret,
    )
}

pub fn verify_key_exchange(
    signer: &Signer,
    our_public_key: &[u8; 32],
    their_identity_key: &[u8; 32],
    their_public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    session::verify_key_exchange::<Hasher, Signer>(
        signer,
        our_public_key,
        their_identity_key,
        their_public_key,
        signature,
    )
}

pub type Channel = channel::Channel<Cipher, Kdf>;

pub fn issue(
    signer: &Signer,
    their_identity_key: &[u8; 32],
    data: Option<&[u8]>,
    channel: &mut Channel,
) -> Result<[u8; 116], Error> {
    cred::issue::<Cipher, Hasher, Kdf, Signer>(signer, their_identity_key, data, channel)
}

pub fn send(
    certifier_identity_key: &[u8; 32],
    signature: &[u8; 64],
    channel: &mut Channel,
) -> Result<[u8; 116], Error> {
    cred::send::<Cipher, Kdf>(certifier_identity_key, signature, channel)
}

pub fn verify(
    their_identity_key: &[u8; 32],
    data: Option<&[u8]>,
    channel: &Channel,
    message: &[u8; 116],
) -> Result<[u8; 32], Error> {
    cred::verify::<Cipher, Hasher, Kdf, Signer>(their_identity_key, data, channel, message)
}
pub fn receive(message: &[u8; 116], channel: &Channel) -> Result<([u8; 32], [u8; 64]), Error> {
    cred::receive::<Cipher, Kdf>(message, channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autograph() {
        let alice_signer = Signer::from([
            51, 45, 77, 34, 55, 79, 178, 70, 245, 26, 9, 86, 12, 200, 101, 230, 7, 253, 207, 52,
            39, 155, 55, 88, 138, 98, 168, 237, 13, 228, 108, 85,
        ]);

        let alice_identity_key = alice_signer.public_key().unwrap();

        let alice_id = [10, 168, 165, 73, 24, 165, 2, 173, 121, 222, 4];

        let (alice_private_key, alice_public_key) = key_pair([
            136, 157, 80, 54, 187, 219, 65, 70, 252, 214, 35, 87, 11, 147, 73, 212, 4, 135, 30,
            229, 37, 30, 185, 243, 3, 212, 39, 116, 93, 181, 30, 226,
        ]);

        let bob_signer = Signer::from([
            120, 33, 116, 237, 141, 102, 87, 151, 140, 107, 246, 105, 106, 246, 241, 233, 124, 112,
            225, 153, 127, 136, 85, 243, 150, 49, 35, 206, 135, 90, 225, 50,
        ]);

        let bob_identity_key = bob_signer.public_key().unwrap();

        let bob_id = [203, 73, 15, 32, 33, 24, 90, 201, 55, 209, 207];

        let (bob_private_key, bob_public_key) = key_pair([
            117, 227, 244, 189, 243, 177, 182, 64, 76, 22, 122, 128, 224, 205, 26, 157, 165, 132,
            159, 182, 32, 166, 89, 54, 69, 186, 146, 90, 42, 177, 226, 165,
        ]);

        let alice_safety_number =
            authenticate(&alice_signer, &alice_id, &bob_identity_key, &bob_id).unwrap();

        let bob_safety_number =
            authenticate(&bob_signer, &bob_id, &alice_identity_key, &alice_id).unwrap();

        assert_eq!(alice_safety_number, bob_safety_number);

        let (alice_secret_key, alice_signature) = key_exchange(
            &alice_signer,
            &alice_private_key,
            &alice_public_key,
            &bob_identity_key,
            &bob_public_key,
            None,
        )
        .unwrap();

        let (bob_secret_key, bob_signature) = key_exchange(
            &bob_signer,
            &bob_private_key,
            &bob_public_key,
            &alice_identity_key,
            &alice_public_key,
            None,
        )
        .unwrap();

        assert_eq!(alice_secret_key, bob_secret_key);

        verify_key_exchange(
            &alice_signer,
            &alice_public_key,
            &bob_identity_key,
            &bob_public_key,
            &bob_signature,
        )
        .unwrap();

        verify_key_exchange(
            &bob_signer,
            &bob_public_key,
            &alice_identity_key,
            &alice_public_key,
            &alice_signature,
        )
        .unwrap();

        let mut alice_channel = Channel::new(&alice_secret_key, &alice_id, &bob_id);

        let mut bob_channel = Channel::new(&bob_secret_key, &bob_id, &alice_id);

        let data = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

        let mut buffer = data.clone();

        let (index, tag) = alice_channel.encrypt(&mut buffer, None).unwrap();

        assert_eq!(index, 1);

        bob_channel.decrypt(index, &mut buffer, &tag, None).unwrap();

        assert_eq!(buffer, data);

        let alice_message = issue(
            &alice_signer,
            &bob_identity_key,
            Some(&data),
            &mut alice_channel,
        )
        .unwrap();

        let bob_message = issue(
            &bob_signer,
            &alice_identity_key,
            Some(&data),
            &mut bob_channel,
        )
        .unwrap();

        let certifier_identity_key =
            verify(&bob_identity_key, Some(&data), &bob_channel, &alice_message).unwrap();

        assert_eq!(certifier_identity_key, alice_identity_key);

        let certifier_identity_key = verify(
            &alice_identity_key,
            Some(&data),
            &alice_channel,
            &bob_message,
        )
        .unwrap();

        assert_eq!(certifier_identity_key, bob_identity_key);
    }
}
