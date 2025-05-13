pub trait ChaCha20Poly1305 {
    fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        assoicated_data: Option<&[u8]>,
        message: &mut [u8],
    ) -> [u8; 16];

    fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        assoicated_data: Option<&[u8]>,
        message: &mut [u8],
        tag: &[u8; 16],
    ) -> bool;
}

pub trait Ed25519Signer {
    fn public_key(&self) -> Option<[u8; 32]>;

    fn sign(&self, message: &[u8]) -> Option<[u8; 64]>;

    fn verify(message: &[u8], public_key: &[u8; 32], signature: &[u8; 64]) -> bool;
}

pub trait Sha512Hasher {
    fn new() -> Self;

    fn update(&mut self, message: &[u8]);

    fn digest(self) -> [u8; 64];
}

pub trait X25519 {
    fn key_pair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]);

    fn key_exchange(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32];
}

pub trait Hkdf {
    fn kdf(ikm: &[u8], context: &[u8]) -> [u8; 32];
}

#[derive(Debug)]
pub enum Error {
    Identity = 1,
    Signing = 2,
    Verification = 3,
    KeyExchange = 4,
    Channel = 5,
    Decryption = 6,
}

pub mod cert {
    use super::{Ed25519Signer, Error, Sha512Hasher};

    pub fn get_identity_key<S: Ed25519Signer>(signer: &S) -> Result<[u8; 32], Error> {
        if let Some(public_key) = signer.public_key() {
            Ok(public_key)
        } else {
            Err(Error::Identity)
        }
    }

    pub fn sign<H: Sha512Hasher, S: Ed25519Signer>(
        signer: &S,
        owner_identity_key: &[u8; 32],
        data: Option<&[u8]>,
    ) -> Result<[u8; 64], Error> {
        let subject = calculate_subject::<H>(owner_identity_key, data);
        if let Some(signature) = signer.sign(&subject) {
            Ok(signature)
        } else {
            Err(Error::Signing)
        }
    }

    fn calculate_subject<H: Sha512Hasher>(
        owner_identity_key: &[u8; 32],
        data: Option<&[u8]>,
    ) -> [u8; 64] {
        let mut hasher = H::new();
        hasher.update(data.unwrap_or_default());
        hasher.update(owner_identity_key);
        hasher.digest()
    }

    pub fn verify<H: Sha512Hasher, S: Ed25519Signer>(
        certifier_identity_key: &[u8; 32],
        signature: &[u8; 64],
        owner_identity_key: &[u8; 32],
        data: Option<&[u8]>,
    ) -> Result<(), Error> {
        let subject = calculate_subject::<H>(owner_identity_key, data);
        if S::verify(&subject, certifier_identity_key, signature) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

pub mod auth {
    use super::{cert::get_identity_key, Ed25519Signer, Error, Sha512Hasher};

    pub fn authenticate<H: Sha512Hasher, S: Ed25519Signer>(
        signer: &S,
        our_id: &[u8],
        their_identity_key: &[u8; 32],
        their_id: &[u8],
    ) -> Result<[u8; 64], Error> {
        let our_identity_key = get_identity_key(signer)?;
        let mut hasher = H::new();
        if their_identity_key[0] > our_identity_key[0] {
            hasher.update(their_identity_key);
            hasher.update(their_id);
            hasher.update(&our_identity_key);
            hasher.update(our_id);
        } else {
            hasher.update(&our_identity_key);
            hasher.update(our_id);
            hasher.update(their_identity_key);
            hasher.update(their_id);
        }
        let mut digest = hasher.digest();
        for _ in 1..5200 {
            let mut h = H::new();
            h.update(&digest);
            digest.copy_from_slice(&h.digest());
        }
        Ok(digest)
    }
}

pub mod session {
    use super::{
        cert::{get_identity_key, sign, verify},
        Ed25519Signer, Error, Hkdf, Sha512Hasher, X25519,
    };

    pub fn key_pair<D: X25519>(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        D::key_pair(seed)
    }

    pub fn key_exchange<D: X25519, H: Sha512Hasher, K: Hkdf, S: Ed25519Signer>(
        signer: &S,
        our_private_key: &[u8; 32],
        our_public_key: &[u8; 32],
        their_identity_key: &[u8; 32],
        their_public_key: &[u8; 32],
        pre_shared_secret: Option<&[u8; 32]>,
    ) -> Result<([u8; 32], [u8; 64]), Error> {
        let our_identity_key = get_identity_key(signer)?;
        let transcript = calculate_transcript::<H>(
            &our_identity_key,
            our_public_key,
            their_identity_key,
            their_public_key,
        );
        let shared_secret = D::key_exchange(our_private_key, their_public_key);
        let secret_key = K::kdf(&shared_secret, &transcript);
        let secret_key = K::kdf(&secret_key, pre_shared_secret.unwrap_or(&[0u8; 32]));
        let signature = sign::<H, S>(signer, their_identity_key, Some(&transcript))?;
        Ok((secret_key, signature))
    }

    fn calculate_transcript<H: Sha512Hasher>(
        our_identity_key: &[u8; 32],
        our_public_key: &[u8; 32],
        their_identity_key: &[u8; 32],
        their_public_key: &[u8; 32],
    ) -> [u8; 64] {
        let mut hasher = H::new();
        if their_identity_key[0] > our_identity_key[0] {
            hasher.update(their_identity_key);
            hasher.update(their_public_key);
            hasher.update(our_identity_key);
            hasher.update(our_public_key);
        } else {
            hasher.update(our_identity_key);
            hasher.update(our_public_key);
            hasher.update(their_identity_key);
            hasher.update(their_public_key);
        }
        hasher.digest()
    }

    pub fn verify_key_exchange<H: Sha512Hasher, S: Ed25519Signer>(
        signer: &S,
        our_public_key: &[u8; 32],
        their_identity_key: &[u8; 32],
        their_public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        let our_identity_key = get_identity_key(signer)?;
        let transcript = calculate_transcript::<H>(
            &our_identity_key,
            our_public_key,
            their_identity_key,
            their_public_key,
        );
        verify::<H, S>(
            their_identity_key,
            signature,
            &our_identity_key,
            Some(&transcript),
        )
        .or(Err(Error::KeyExchange))
    }
}

pub mod channel {
    use super::{ChaCha20Poly1305, Error, Hkdf};
    use core::marker::PhantomData;

    #[repr(C)]
    pub struct Channel<C, K> {
        sending_key: [u8; 32],
        receiving_key: [u8; 32],
        sending_index: u32,
        c: PhantomData<C>,
        k: PhantomData<K>,
    }

    impl<C: ChaCha20Poly1305, K: Hkdf> Channel<C, K> {
        pub fn new(secret_key: &[u8; 32], our_id: &[u8], their_id: &[u8]) -> Self {
            Self {
                sending_key: K::kdf(secret_key, our_id),
                receiving_key: K::kdf(secret_key, their_id),
                sending_index: 0,
                c: PhantomData::<C>,
                k: PhantomData::<K>,
            }
        }

        pub fn encrypt(
            &mut self,
            message: &mut [u8],
            associated_data: Option<&[u8]>,
        ) -> Result<(u32, [u8; 16]), Error> {
            if self.sending_index == u32::MAX {
                return Err(Error::Channel);
            }
            self.sending_index += 1;
            let nonce = calculate_nonce(self.sending_index);
            let tag = C::encrypt(&self.sending_key, &nonce, associated_data, message);
            Ok((self.sending_index, tag))
        }

        pub fn decrypt(
            &self,
            index: u32,
            message: &mut [u8],
            tag: &[u8; 16],
            associated_data: Option<&[u8]>,
        ) -> Result<(), Error> {
            let nonce = calculate_nonce(index);
            if C::decrypt(&self.receiving_key, &nonce, associated_data, message, tag) {
                Ok(())
            } else {
                Err(Error::Decryption)
            }
        }
    }

    fn calculate_nonce(index: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[8..12].copy_from_slice(&index.to_be_bytes());
        nonce
    }
}

pub mod cred {
    use super::{
        cert::{get_identity_key, sign, verify as verify_ownership},
        channel::Channel,
        ChaCha20Poly1305, Ed25519Signer, Error, Hkdf, Sha512Hasher,
    };

    pub fn issue<C: ChaCha20Poly1305, H: Sha512Hasher, K: Hkdf, S: Ed25519Signer>(
        signer: &S,
        their_identity_key: &[u8; 32],
        data: Option<&[u8]>,
        channel: &mut Channel<C, K>,
    ) -> Result<[u8; 116], Error> {
        let our_identity_key = get_identity_key::<S>(signer)?;
        let signature = sign::<H, S>(signer, their_identity_key, data)?;
        send::<C, K>(&our_identity_key, &signature, channel)
    }

    pub fn send<C: ChaCha20Poly1305, K: Hkdf>(
        certifier_identity_key: &[u8; 32],
        signature: &[u8; 64],
        channel: &mut Channel<C, K>,
    ) -> Result<[u8; 116], Error> {
        let mut message = [0u8; 116];
        message[4..36].copy_from_slice(certifier_identity_key);
        message[36..100].copy_from_slice(signature);
        let (index, tag) = channel.encrypt(&mut message[4..100], None)?;
        message[0..4].copy_from_slice(&index.to_be_bytes());
        message[100..116].copy_from_slice(&tag);
        Ok(message)
    }

    pub fn verify<C: ChaCha20Poly1305, H: Sha512Hasher, K: Hkdf, S: Ed25519Signer>(
        their_identity_key: &[u8; 32],
        data: Option<&[u8]>,
        channel: &Channel<C, K>,
        message: &[u8; 116],
    ) -> Result<[u8; 32], Error> {
        let (certifier_identity_key, signature) = receive::<C, K>(message, channel)?;
        verify_ownership::<H, S>(
            &certifier_identity_key,
            &signature,
            their_identity_key,
            data,
        )?;
        Ok(certifier_identity_key)
    }

    pub fn receive<C: ChaCha20Poly1305, K: Hkdf>(
        message: &[u8; 116],
        channel: &Channel<C, K>,
    ) -> Result<([u8; 32], [u8; 64]), Error> {
        let index = u32::from_be_bytes(message[0..4].try_into().unwrap());
        let mut credential: [u8; 96] = message[4..100].try_into().unwrap();
        let tag: [u8; 16] = message[100..116].try_into().unwrap();
        channel.decrypt(index, &mut credential, &tag, None)?;
        let certifier_identity_key: [u8; 32] = credential[0..32].try_into().unwrap();
        let signature: [u8; 64] = credential[32..96].try_into().unwrap();
        Ok((certifier_identity_key, signature))
    }
}
