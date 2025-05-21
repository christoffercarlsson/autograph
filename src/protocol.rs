pub const SECRET_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

pub type SecretKey = [u8; SECRET_KEY_SIZE];
pub type Nonce = [u8; NONCE_SIZE];
pub type Tag = [u8; TAG_SIZE];

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SEED_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;

pub type PrivateKey = [u8; PRIVATE_KEY_SIZE];
pub type PublicKey = [u8; PUBLIC_KEY_SIZE];
pub type Seed = [u8; SEED_SIZE];
pub type SharedSecret = [u8; SHARED_SECRET_SIZE];

pub const DIGEST_SIZE: usize = 64;

pub type Digest = [u8; DIGEST_SIZE];

pub const IDENTITY_SECRET_KEY_SIZE: usize = 32;
pub const IDENTITY_PRIVATE_KEY_SIZE: usize = 32;
pub const IDENTITY_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

pub type IdentitySecretKey = [u8; IDENTITY_SECRET_KEY_SIZE];
pub type IdentityPrivateKey = [u8; IDENTITY_PRIVATE_KEY_SIZE];
pub type IdentityKey = [u8; IDENTITY_KEY_SIZE];
pub type Signature = [u8; SIGNATURE_SIZE];

#[derive(Debug)]
pub enum Error {
    Identity = 1,
    Signing = 2,
    Verification = 3,
    KeyExchange = 4,
    Session = 5,
    Channel = 6,
    Decryption = 7,
}

pub trait Aead {
    fn encrypt(
        key: &SecretKey,
        nonce: &Nonce,
        associated_data: Option<&[u8]>,
        message: &mut [u8],
    ) -> Tag;

    fn decrypt(
        key: &SecretKey,
        nonce: &Nonce,
        associated_data: Option<&[u8]>,
        message: &mut [u8],
        tag: &Tag,
    ) -> bool;
}

pub trait DiffieHellman {
    fn calculate_key_pair(seed: Seed) -> (PrivateKey, PublicKey);

    fn calculate_shared_secret(private_key: &PrivateKey, public_key: &PublicKey) -> SharedSecret;
}

pub trait Hasher {
    fn new() -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Digest;
}

pub trait Kdf {
    fn derive_key(ikm: &[u8], context: &[u8], okm: &mut [u8]);
}

pub trait Signer {
    fn from_bytes(secret: IdentitySecretKey) -> Self;

    fn get_identity_key(&self) -> Option<IdentityKey>;

    fn sign(&self, subject: &[u8]) -> Option<Signature>;

    fn verify(subject: &[u8], public_key: &IdentityKey, signature: &Signature) -> bool;
}

fn get_identity_key<S: Signer>(signer: &S) -> Result<IdentityKey, Error> {
    if let Some(public_key) = signer.get_identity_key() {
        Ok(public_key)
    } else {
        Err(Error::Identity)
    }
}

fn derive_key<K: Kdf>(ikm: &[u8], context: &[u8]) -> SecretKey {
    let mut secret_key = [0u8; SECRET_KEY_SIZE];
    K::derive_key(ikm, context, &mut secret_key);
    secret_key
}

pub mod cert {
    use super::{Digest, Error, Hasher, IdentityKey, Signature, Signer};

    pub fn sign<H: Hasher, S: Signer>(
        signer: &S,
        owner_identity_key: &IdentityKey,
        data: Option<&[u8]>,
    ) -> Result<Signature, Error> {
        let subject = calculate_subject::<H>(owner_identity_key, data);
        if let Some(signature) = signer.sign(&subject) {
            Ok(signature)
        } else {
            Err(Error::Signing)
        }
    }

    fn calculate_subject<H: Hasher>(
        owner_identity_key: &IdentityKey,
        data: Option<&[u8]>,
    ) -> Digest {
        let mut hasher = H::new();
        hasher.update(data.unwrap_or_default());
        hasher.update(owner_identity_key);
        hasher.finalize()
    }

    pub fn verify<H: Hasher, S: Signer>(
        certifier_identity_key: &IdentityKey,
        signature: &Signature,
        owner_identity_key: &IdentityKey,
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
    use super::{get_identity_key, Digest, Error, Hasher, IdentityKey, Signer, DIGEST_SIZE};

    const SAFETY_NUMBER_ITERATIONS: usize = 5200;
    const SAFETY_NUMBER_DIVISOR: u32 = 100000;

    pub type SafetyNumber = [u8; DIGEST_SIZE];

    pub fn authenticate<H: Hasher, S: Signer>(
        signer: &S,
        our_id: &[u8],
        their_identity_key: &IdentityKey,
        their_id: &[u8],
    ) -> Result<Digest, Error> {
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
        let mut digest = hasher.finalize();
        for _ in 1..SAFETY_NUMBER_ITERATIONS {
            let mut h = H::new();
            h.update(&digest);
            digest.copy_from_slice(&h.finalize());
        }
        Ok(digest)
    }

    pub fn encode(digest: &Digest) -> SafetyNumber {
        let mut safety_number = [0u8; DIGEST_SIZE];
        for i in (0..DIGEST_SIZE).step_by(4) {
            let n = u32::from_be_bytes([digest[i], digest[i + 1], digest[i + 2], digest[i + 3]])
                % SAFETY_NUMBER_DIVISOR;
            safety_number[i..(i + 4)].copy_from_slice(&n.to_be_bytes());
        }
        safety_number
    }
}

pub mod session {
    use super::{
        auth::{authenticate, encode, SafetyNumber},
        cert::{sign, verify},
        derive_key, get_identity_key, DiffieHellman, Digest, Error, Hasher, IdentityKey, Kdf,
        PrivateKey, PublicKey, SecretKey, Seed, Signature, Signer, SECRET_KEY_SIZE,
    };
    use core::marker::PhantomData;

    pub fn key_exchange<D: DiffieHellman, H: Hasher, K: Kdf, S: Signer>(
        signer: &S,
        our_private_key: &PrivateKey,
        our_public_key: &PublicKey,
        their_identity_key: &IdentityKey,
        their_public_key: &PublicKey,
        pre_shared_secret: Option<&SecretKey>,
    ) -> Result<(SecretKey, Signature), Error> {
        let our_identity_key = get_identity_key::<S>(signer)?;
        let transcript = calculate_transcript::<H>(
            &our_identity_key,
            our_public_key,
            their_identity_key,
            their_public_key,
        );
        let shared_secret = D::calculate_shared_secret(our_private_key, their_public_key);
        let secret_key = derive_key::<K>(&shared_secret, &transcript);
        let secret_key = derive_key::<K>(
            &secret_key,
            pre_shared_secret.unwrap_or(&[0u8; SECRET_KEY_SIZE]),
        );
        let signature = sign::<H, S>(signer, their_identity_key, Some(&transcript))?;
        Ok((secret_key, signature))
    }

    fn calculate_transcript<H: Hasher>(
        our_identity_key: &IdentityKey,
        our_public_key: &PublicKey,
        their_identity_key: &IdentityKey,
        their_public_key: &PublicKey,
    ) -> Digest {
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
        hasher.finalize()
    }

    pub fn verify_key_exchange<H: Hasher, S: Signer>(
        signer: &S,
        our_public_key: &PublicKey,
        their_identity_key: &IdentityKey,
        their_public_key: &PublicKey,
        signature: &Signature,
    ) -> Result<(), Error> {
        let our_identity_key = get_identity_key::<S>(signer)?;
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

    pub struct Session<D, H, K, S> {
        signer: S,
        private_key: PrivateKey,
        public_key: PublicKey,
        their_identity_key: Option<IdentityKey>,
        their_public_key: Option<PublicKey>,
        d: PhantomData<D>,
        h: PhantomData<H>,
        k: PhantomData<K>,
    }

    impl<D: DiffieHellman, H: Hasher, K: Kdf, S: Signer> Session<D, H, K, S> {
        pub fn new(signer: S, seed: Seed) -> Self {
            let (private_key, public_key) = D::calculate_key_pair(seed);
            Self {
                signer,
                private_key,
                public_key,
                their_identity_key: None,
                their_public_key: None,
                d: PhantomData::<D>,
                h: PhantomData::<H>,
                k: PhantomData::<K>,
            }
        }

        pub fn start(&self) -> Result<(IdentityKey, PublicKey), Error> {
            let identity_key = get_identity_key::<S>(&self.signer)?;
            Ok((identity_key, self.public_key))
        }

        pub fn key_exchange(
            &mut self,
            their_identity_key: IdentityKey,
            their_public_key: PublicKey,
            pre_shared_secret: Option<&SecretKey>,
        ) -> Result<(SecretKey, Signature), Error> {
            self.their_identity_key = Some(their_identity_key);
            self.their_public_key = Some(their_public_key);
            key_exchange::<D, H, K, S>(
                &self.signer,
                &self.private_key,
                &self.public_key,
                &self.their_identity_key.unwrap(),
                &self.their_public_key.unwrap(),
                pre_shared_secret,
            )
        }

        pub fn authenticate(&self, our_id: &[u8], their_id: &[u8]) -> Result<SafetyNumber, Error> {
            if self.their_identity_key.is_some() {
                let digest = authenticate::<H, S>(
                    &self.signer,
                    our_id,
                    &self.their_identity_key.unwrap(),
                    their_id,
                )?;
                let safety_number = encode(&digest);
                Ok(safety_number)
            } else {
                Err(Error::Session)
            }
        }

        pub fn verify_key_exchange(self, signature: &Signature) -> Result<S, Error> {
            if self.their_identity_key.is_some() && self.their_public_key.is_some() {
                verify_key_exchange::<H, S>(
                    &self.signer,
                    &self.public_key,
                    &self.their_identity_key.unwrap(),
                    &self.their_public_key.unwrap(),
                    signature,
                )?;
                Ok(self.signer)
            } else {
                Err(Error::Session)
            }
        }
    }
}

pub mod channel {
    use super::{derive_key, Aead, Error, Kdf, Nonce, SecretKey, Tag, NONCE_SIZE, SECRET_KEY_SIZE};
    use core::marker::PhantomData;

    pub const STATE_SIZE: usize = SECRET_KEY_SIZE * 2 + 8;

    pub type State = [u8; STATE_SIZE];

    const RECEIVING_KEY_OFFSET: usize = SECRET_KEY_SIZE;
    const SENDING_INDEX_OFFSET: usize = RECEIVING_KEY_OFFSET + SECRET_KEY_SIZE;

    pub struct Channel<A, K> {
        sending_key: SecretKey,
        receiving_key: SecretKey,
        sending_index: u64,
        a: PhantomData<A>,
        k: PhantomData<K>,
    }

    impl<A: Aead, K: Kdf> Channel<A, K> {
        pub fn new(secret_key: &SecretKey, our_id: &[u8], their_id: &[u8]) -> Self {
            Self {
                sending_key: derive_key::<K>(secret_key, our_id),
                receiving_key: derive_key::<K>(secret_key, their_id),
                sending_index: 0,
                a: PhantomData::<A>,
                k: PhantomData::<K>,
            }
        }

        pub fn encrypt(
            &mut self,
            message: &mut [u8],
            associated_data: Option<&[u8]>,
        ) -> Result<(u64, Tag), Error> {
            if self.sending_index == u64::MAX {
                return Err(Error::Channel);
            }
            self.sending_index += 1;
            let nonce = Self::calculate_nonce(self.sending_index);
            let tag = A::encrypt(&self.sending_key, &nonce, associated_data, message);
            Ok((self.sending_index, tag))
        }

        fn calculate_nonce(index: u64) -> Nonce {
            let mut nonce = [0u8; NONCE_SIZE];
            nonce[(NONCE_SIZE - 8)..].copy_from_slice(&index.to_be_bytes());
            nonce
        }

        pub fn decrypt(
            &self,
            index: u64,
            message: &mut [u8],
            tag: &Tag,
            associated_data: Option<&[u8]>,
        ) -> Result<(), Error> {
            let nonce = Self::calculate_nonce(index);
            if A::decrypt(&self.receiving_key, &nonce, associated_data, message, tag) {
                Ok(())
            } else {
                Err(Error::Decryption)
            }
        }

        pub fn open(state: State) -> Self {
            let mut sending_key = [0u8; SECRET_KEY_SIZE];
            let mut receiving_key = [0u8; SECRET_KEY_SIZE];
            sending_key.copy_from_slice(&state[..RECEIVING_KEY_OFFSET]);
            receiving_key.copy_from_slice(&state[RECEIVING_KEY_OFFSET..SENDING_INDEX_OFFSET]);
            let sending_index =
                u64::from_be_bytes(state[SENDING_INDEX_OFFSET..].try_into().unwrap());
            Self {
                sending_key,
                receiving_key,
                sending_index,
                a: PhantomData::<A>,
                k: PhantomData::<K>,
            }
        }

        pub fn close(self) -> State {
            let mut state = [0u8; STATE_SIZE];
            state[..RECEIVING_KEY_OFFSET].copy_from_slice(&self.sending_key);
            state[RECEIVING_KEY_OFFSET..SENDING_INDEX_OFFSET].copy_from_slice(&self.receiving_key);
            state[SENDING_INDEX_OFFSET..].copy_from_slice(&self.sending_index.to_be_bytes());
            state
        }
    }
}

pub mod cred {
    use super::{
        cert::sign, channel::Channel, get_identity_key, Aead, Error, Hasher, IdentityKey, Kdf,
        Signature, Signer, Tag, IDENTITY_KEY_SIZE, SIGNATURE_SIZE, TAG_SIZE,
    };

    pub const MESSAGE_SIZE: usize = 8 + IDENTITY_KEY_SIZE + SIGNATURE_SIZE + TAG_SIZE;

    pub type Message = [u8; MESSAGE_SIZE];

    const IDENTITY_KEY_OFFSET: usize = 8;
    const SIGNATURE_OFFSET: usize = IDENTITY_KEY_OFFSET + IDENTITY_KEY_SIZE;
    const TAG_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SIZE;

    const CREDENTIAL_SIZE: usize = IDENTITY_KEY_SIZE + SIGNATURE_SIZE;

    type Credential = [u8; CREDENTIAL_SIZE];

    pub fn issue<A: Aead, H: Hasher, K: Kdf, S: Signer>(
        signer: &S,
        their_identity_key: &IdentityKey,
        data: Option<&[u8]>,
        channel: &mut Channel<A, K>,
    ) -> Result<Message, Error> {
        let our_identity_key = get_identity_key::<S>(signer)?;
        let signature = sign::<H, S>(signer, their_identity_key, data)?;
        send::<A, K>(&our_identity_key, &signature, channel)
    }

    pub fn send<A: Aead, K: Kdf>(
        certifier_identity_key: &IdentityKey,
        signature: &Signature,
        channel: &mut Channel<A, K>,
    ) -> Result<Message, Error> {
        let mut message = [0u8; MESSAGE_SIZE];
        message[IDENTITY_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(certifier_identity_key);
        message[SIGNATURE_OFFSET..TAG_OFFSET].copy_from_slice(signature);
        let (index, tag) = channel.encrypt(&mut message[IDENTITY_KEY_OFFSET..TAG_OFFSET], None)?;
        message[..IDENTITY_KEY_OFFSET].copy_from_slice(&index.to_be_bytes());
        message[TAG_OFFSET..].copy_from_slice(&tag);
        Ok(message)
    }

    pub fn verify<A: Aead, H: Hasher, K: Kdf, S: Signer>(
        their_identity_key: &IdentityKey,
        data: Option<&[u8]>,
        channel: &Channel<A, K>,
        message: &Message,
    ) -> Result<IdentityKey, Error> {
        let (certifier_identity_key, signature) = receive::<A, K>(message, channel)?;
        super::cert::verify::<H, S>(
            &certifier_identity_key,
            &signature,
            their_identity_key,
            data,
        )?;
        Ok(certifier_identity_key)
    }

    pub fn receive<A: Aead, K: Kdf>(
        message: &Message,
        channel: &Channel<A, K>,
    ) -> Result<(IdentityKey, Signature), Error> {
        let index = u64::from_be_bytes(message[..IDENTITY_KEY_OFFSET].try_into().unwrap());
        let mut credential: Credential =
            message[IDENTITY_KEY_OFFSET..TAG_OFFSET].try_into().unwrap();
        let tag: Tag = message[TAG_OFFSET..].try_into().unwrap();
        channel.decrypt(index, &mut credential, &tag, None)?;
        let certifier_identity_key: IdentityKey =
            credential[..IDENTITY_KEY_SIZE].try_into().unwrap();
        let signature: Signature = credential[IDENTITY_KEY_SIZE..CREDENTIAL_SIZE]
            .try_into()
            .unwrap();
        Ok((certifier_identity_key, signature))
    }
}
