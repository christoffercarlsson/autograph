#![no_std]

extern crate ed25519_dalek;
extern crate stedy;
extern crate x25519_dalek;

mod primitive;
mod protocol;

pub use crate::{
    primitive::Ed25519Signer,
    protocol::{
        Digest, Error, IdentityKey, PrivateKey, PublicKey, SecretKey, Seed, Signature, Signer,
    },
};
use crate::{
    primitive::{ChaCha20Poly1305, Ed25519Verifier, Hkdf, Sha512Hasher, X25519},
    protocol::IDENTITY_SECRET_KEY_SIZE,
};

#[cfg(feature = "getrandom")]
pub fn generate_signer() -> Option<Ed25519Signer> {
    let secret = generate_bytes::<IDENTITY_SECRET_KEY_SIZE>()?;
    Some(Ed25519Signer::from_bytes(secret))
}

#[cfg(feature = "getrandom")]
fn generate_bytes<const BYTES: usize>() -> Option<[u8; BYTES]> {
    if let Ok(mut rng) = stedy::Rng::new() {
        let mut seed = [0u8; BYTES];
        rng.fill(&mut seed);
        Some(seed)
    } else {
        None
    }
}

pub mod auth {
    use super::{Digest, Error, IdentityKey, Sha512Hasher, Signer};

    pub type SafetyNumber = crate::protocol::auth::SafetyNumber;

    pub fn authenticate<S: Signer>(
        signer: &S,
        our_id: &[u8],
        their_identity_key: &IdentityKey,
        their_id: &[u8],
    ) -> Result<Digest, Error> {
        crate::protocol::auth::authenticate::<Sha512Hasher, S>(
            signer,
            our_id,
            their_identity_key,
            their_id,
        )
    }

    pub fn encode(digest: &Digest) -> SafetyNumber {
        crate::protocol::auth::encode(digest)
    }
}

pub mod cert {
    use super::{Ed25519Verifier, Error, IdentityKey, Sha512Hasher, Signature, Signer};

    pub fn sign<S: Signer>(
        signer: &S,
        owner_identity_key: &IdentityKey,
        data: Option<&[u8]>,
    ) -> Result<Signature, Error> {
        crate::protocol::cert::sign::<Sha512Hasher, S>(signer, owner_identity_key, data)
    }

    pub fn verify(
        certifier_identity_key: &IdentityKey,
        signature: &Signature,
        owner_identity_key: &IdentityKey,
        data: Option<&[u8]>,
    ) -> Result<(), Error> {
        crate::protocol::cert::verify::<Sha512Hasher, Ed25519Verifier>(
            certifier_identity_key,
            signature,
            owner_identity_key,
            data,
        )
    }
}

pub mod session {
    use super::{
        generate_bytes, Error, Hkdf, IdentityKey, PrivateKey, PublicKey, SecretKey, Seed,
        Sha512Hasher, Signature, Signer, X25519,
    };
    use crate::protocol::{DiffieHellman, SEED_SIZE};

    pub fn calculate_key_pair(seed: Seed) -> (PrivateKey, PublicKey) {
        X25519::calculate_key_pair(seed)
    }

    #[cfg(feature = "getrandom")]
    pub fn generate_key_pair() -> Option<(PrivateKey, PublicKey)> {
        if let Some(seed) = generate_seed() {
            let key_pair = calculate_key_pair(seed);
            Some(key_pair)
        } else {
            None
        }
    }

    #[cfg(feature = "getrandom")]
    fn generate_seed() -> Option<Seed> {
        generate_bytes::<SEED_SIZE>()
    }

    pub fn key_exchange<S: Signer>(
        signer: &S,
        our_private_key: &PrivateKey,
        our_public_key: &PublicKey,
        their_identity_key: &IdentityKey,
        their_public_key: &PublicKey,
        pre_shared_secret: Option<&SecretKey>,
    ) -> Result<(SecretKey, Signature), Error> {
        crate::protocol::session::key_exchange::<X25519, Sha512Hasher, Hkdf, S>(
            signer,
            our_private_key,
            our_public_key,
            their_identity_key,
            their_public_key,
            pre_shared_secret,
        )
    }

    pub fn verify_key_exchange<S: Signer>(
        signer: &S,
        our_public_key: &PublicKey,
        their_identity_key: &IdentityKey,
        their_public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Error> {
        crate::protocol::session::verify_key_exchange::<Sha512Hasher, S>(
            signer,
            our_public_key,
            their_identity_key,
            their_public_key,
            signature,
        )
    }

    pub type Session<S> = crate::protocol::session::Session<X25519, Sha512Hasher, Hkdf, S>;

    #[cfg(feature = "getrandom")]
    pub fn generate_session<S: Signer>(signer: S) -> Option<Session<S>> {
        if let Some(seed) = generate_seed() {
            let session = Session::new(signer, seed);
            Some(session)
        } else {
            None
        }
    }
}

pub mod channel {
    use super::{ChaCha20Poly1305, Hkdf};

    pub type State = crate::protocol::channel::State;
    pub type Channel = crate::protocol::channel::Channel<ChaCha20Poly1305, Hkdf>;
}

pub mod cred {
    use super::{
        channel::Channel, ChaCha20Poly1305, Ed25519Verifier, Error, Hkdf, IdentityKey,
        Sha512Hasher, Signature, Signer,
    };

    pub type Message = crate::protocol::cred::Message;

    pub fn issue<S: Signer>(
        signer: &S,
        their_identity_key: &IdentityKey,
        data: Option<&[u8]>,
        channel: &mut Channel,
    ) -> Result<Message, Error> {
        crate::protocol::cred::issue::<ChaCha20Poly1305, Sha512Hasher, Hkdf, S>(
            signer,
            their_identity_key,
            data,
            channel,
        )
    }

    pub fn send(
        certifier_identity_key: &IdentityKey,
        signature: &Signature,
        channel: &mut Channel,
    ) -> Result<Message, Error> {
        crate::protocol::cred::send::<ChaCha20Poly1305, Hkdf>(
            certifier_identity_key,
            signature,
            channel,
        )
    }

    pub fn verify(
        their_identity_key: &IdentityKey,
        data: Option<&[u8]>,
        channel: &Channel,
        message: &Message,
    ) -> Result<IdentityKey, Error> {
        crate::protocol::cred::verify::<ChaCha20Poly1305, Sha512Hasher, Hkdf, Ed25519Verifier>(
            their_identity_key,
            data,
            channel,
            message,
        )
    }

    pub fn receive(
        message: &Message,
        channel: &Channel,
    ) -> Result<(IdentityKey, Signature), Error> {
        crate::protocol::cred::receive::<ChaCha20Poly1305, Hkdf>(message, channel)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        channel::Channel,
        cred::{issue, verify},
        generate_signer,
        session::generate_session,
    };

    #[test]
    fn test_autograph() {
        let alice_signer = generate_signer().unwrap();

        let alice_id = [10, 168, 165, 73, 24, 165, 2, 173, 121, 222, 4];

        let bob_signer = generate_signer().unwrap();

        let bob_id = [203, 73, 15, 32, 33, 24, 90, 201, 55, 209, 207];

        let mut alice_session = generate_session(alice_signer).unwrap();

        let (alice_identity_key, alice_public_key) = alice_session.start().unwrap();

        let mut bob_session = generate_session(bob_signer).unwrap();

        let (bob_identity_key, bob_public_key) = bob_session.start().unwrap();

        let (alice_secret_key, alice_signature) = alice_session
            .key_exchange(bob_identity_key, bob_public_key, None)
            .unwrap();

        let (bob_secret_key, bob_signature) = bob_session
            .key_exchange(alice_identity_key, alice_public_key, None)
            .unwrap();

        assert_eq!(alice_secret_key, bob_secret_key);

        let alice_safety_number = alice_session.authenticate(&alice_id, &bob_id).unwrap();
        let bob_safety_number = bob_session.authenticate(&bob_id, &alice_id).unwrap();

        assert_eq!(alice_safety_number, bob_safety_number);

        let alice_signer = alice_session.verify_key_exchange(&bob_signature).unwrap();
        let bob_signer = bob_session.verify_key_exchange(&alice_signature).unwrap();

        let mut alice_channel = Channel::new(&alice_secret_key, &alice_id, &bob_id);
        let mut bob_channel = Channel::new(&bob_secret_key, &bob_id, &alice_id);

        let data = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

        let mut buffer = data.clone();

        let (index, tag) = alice_channel.encrypt(&mut buffer, None).unwrap();

        assert_eq!(index, 1);
        assert_ne!(buffer, data);

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
