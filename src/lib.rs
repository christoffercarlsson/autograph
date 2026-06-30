#![no_std]
#![deny(clippy::unwrap_used)]

use core::marker::PhantomData;

#[allow(private_bounds)]
pub trait ByteArray: AsRef<[u8]> + AsMut<[u8]> + Eq + Ord + Sealed {
    const SIZE: usize;

    fn new() -> Self;
}

impl<const N: usize> ByteArray for [u8; N] {
    const SIZE: usize = N;

    fn new() -> Self {
        [0u8; N]
    }
}

trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}

pub trait Aead {
    type SecretKey: ByteArray;
    type Nonce: ByteArray;
    type Tag: ByteArray;

    fn encrypt(
        key: &Self::SecretKey,
        nonce: &Self::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
    ) -> Self::Tag;

    fn decrypt(
        key: &Self::SecretKey,
        nonce: &Self::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
        tag: &Self::Tag,
    ) -> bool;

    fn increment_nonce(nonce: &mut Self::Nonce) -> Option<u64>;

    fn read_index(nonce: &Self::Nonce) -> u64;
}

pub trait Csprng {
    fn fill(&mut self, bytes: &mut [u8]);
}

pub trait KeyExchange {
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type SharedSecret: ByteArray;

    fn generate_key_pair(csprng: &mut impl Csprng) -> (Self::PrivateKey, Self::PublicKey);

    fn key_exchange(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret;
}

pub trait Hasher {
    type Digest: ByteArray;

    fn new() -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Digest;
}

pub trait Kdf {
    fn kdf(ikm: &[u8], salt: Option<&[u8]>, context: &[u8], okm: &mut [u8]);
}

pub trait Signer {
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Signature: ByteArray;

    fn public_key(&self) -> Option<Self::PublicKey>;

    fn sign(&self, subject: &[u8]) -> Option<Self::Signature>;

    fn verify(subject: &[u8], public_key: &Self::PublicKey, signature: &Self::Signature) -> bool;
}

pub struct Credential<H: Hasher, S: Signer> {
    _marker: PhantomData<(H, S)>,
}

impl<H: Hasher, S: Signer> Credential<H, S> {
    pub fn claim(signer: &S, our_data: &[u8]) -> Option<S::Signature> {
        signer.sign(our_data)
    }

    pub fn endorse(
        signer: &S,
        our_data: Option<&[u8]>,
        their_public_key: &S::PublicKey,
        their_data: &[u8],
        their_signature: &S::Signature,
    ) -> Option<S::Signature> {
        if !S::verify(their_data, their_public_key, their_signature) {
            return None;
        }
        let mut hasher = H::new();
        hasher.update(their_data);
        hasher.update(our_data.unwrap_or_default());
        hasher.update(their_public_key.as_ref());
        signer.sign(hasher.finalize().as_ref())
    }

    pub fn generate_challenge(csprng: &mut impl Csprng, challenge: &mut [u8]) {
        csprng.fill(challenge);
    }

    pub fn present(signer: &S, our_data: &[u8], challenge: &[u8]) -> Option<S::Signature> {
        let mut hasher = H::new();
        hasher.update(our_data);
        hasher.update(challenge);
        signer.sign(hasher.finalize().as_ref())
    }

    pub fn verify(
        our_challenge: &[u8],
        their_public_key: &S::PublicKey,
        their_data: &[u8],
        their_signature: &S::Signature,
        endorser_public_key: &S::PublicKey,
        endorser_data: Option<&[u8]>,
        endorser_signature: &S::Signature,
    ) -> bool {
        let mut hasher = H::new();
        hasher.update(their_data);
        hasher.update(endorser_data.unwrap_or_default());
        hasher.update(their_public_key.as_ref());
        if !S::verify(
            hasher.finalize().as_ref(),
            endorser_public_key,
            endorser_signature,
        ) {
            return false;
        }
        let mut hasher = H::new();
        hasher.update(their_data);
        hasher.update(our_challenge);
        S::verify(
            hasher.finalize().as_ref(),
            their_public_key,
            their_signature,
        )
    }
}

pub struct Handshake<'a, D: KeyExchange, H: Hasher, K: Kdf, S: Signer> {
    private_key: &'a D::PrivateKey,
    public_key: &'a D::PublicKey,
    ephemeral_private_key: &'a D::PrivateKey,
    ephemeral_public_key: &'a D::PublicKey,
    pre_shared_key: Option<&'a [u8]>,
    _marker: PhantomData<(H, K, S)>,
}

impl<'a, D: KeyExchange, H: Hasher, K: Kdf, S: Signer> Handshake<'a, D, H, K, S> {
    pub fn new(
        private_key: &'a D::PrivateKey,
        public_key: &'a D::PublicKey,
        ephemeral_private_key: &'a D::PrivateKey,
        ephemeral_public_key: &'a D::PublicKey,
        pre_shared_key: Option<&'a [u8]>,
    ) -> Self {
        Self {
            private_key,
            public_key,
            ephemeral_private_key,
            ephemeral_public_key,
            pre_shared_key,
            _marker: PhantomData,
        }
    }

    pub fn generate_key_pair(csprng: &mut impl Csprng) -> (D::PrivateKey, D::PublicKey) {
        D::generate_key_pair(csprng)
    }

    pub fn certify(&self, signer: &S) -> Option<S::Signature> {
        let mut hasher = H::new();
        hasher.update(self.public_key.as_ref());
        hasher.update(self.ephemeral_public_key.as_ref());
        signer.sign(hasher.finalize().as_ref())
    }

    pub fn authenticate(
        &self,
        signer: &S,
        our_id: &[u8],
        their_identity_key: &S::PublicKey,
        their_public_key: &D::PublicKey,
        their_id: &[u8],
    ) -> Option<H::Digest> {
        let our_identity_key = &signer.public_key()?;
        if our_identity_key == their_identity_key || self.public_key == their_public_key {
            return None;
        }
        let mut hasher = H::new();
        if their_identity_key > our_identity_key {
            hasher.update(their_identity_key.as_ref());
            hasher.update(their_public_key.as_ref());
            hasher.update(their_id);
            hasher.update(our_identity_key.as_ref());
            hasher.update(self.public_key.as_ref());
            hasher.update(our_id);
        } else {
            hasher.update(our_identity_key.as_ref());
            hasher.update(self.public_key.as_ref());
            hasher.update(our_id);
            hasher.update(their_identity_key.as_ref());
            hasher.update(their_public_key.as_ref());
            hasher.update(their_id);
        }
        Some(hasher.finalize())
    }

    pub fn initiator(
        self,
        signer: &S,
        their_identity_key: &S::PublicKey,
        their_public_key: &D::PublicKey,
        their_ephemeral_key: &D::PublicKey,
        their_signature: &S::Signature,
        secret_key: &mut [u8],
    ) -> Option<S::Signature> {
        let mut hasher = H::new();
        hasher.update(their_public_key.as_ref());
        hasher.update(their_ephemeral_key.as_ref());
        if !S::verify(
            hasher.finalize().as_ref(),
            their_identity_key,
            their_signature,
        ) {
            return None;
        }
        let mut hasher = H::new();
        hasher.update(their_public_key.as_ref());
        hasher.update(their_ephemeral_key.as_ref());
        hasher.update(self.public_key.as_ref());
        hasher.update(self.ephemeral_public_key.as_ref());
        let session_id = hasher.finalize();
        let our_signature = signer.sign(session_id.as_ref())?;
        let dh1 = D::key_exchange(self.ephemeral_private_key, their_public_key);
        let dh2 = D::key_exchange(self.private_key, their_ephemeral_key);
        self.derive_secret_key(dh1, dh2, secret_key);
        Some(our_signature)
    }

    pub fn responder(
        self,
        their_identity_key: &S::PublicKey,
        their_public_key: &D::PublicKey,
        their_ephemeral_key: &D::PublicKey,
        their_signature: &S::Signature,
        secret_key: &mut [u8],
    ) -> bool {
        let mut hasher = H::new();
        hasher.update(self.public_key.as_ref());
        hasher.update(self.ephemeral_public_key.as_ref());
        hasher.update(their_public_key.as_ref());
        hasher.update(their_ephemeral_key.as_ref());
        let session_id = hasher.finalize();
        if !S::verify(session_id.as_ref(), their_identity_key, their_signature) {
            return false;
        }
        let dh1 = D::key_exchange(self.private_key, their_ephemeral_key);
        let dh2 = D::key_exchange(self.ephemeral_private_key, their_public_key);
        self.derive_secret_key(dh1, dh2, secret_key);
        true
    }

    fn derive_secret_key(self, dh1: D::SharedSecret, dh2: D::SharedSecret, secret_key: &mut [u8]) {
        let mut hasher = H::new();
        hasher.update(dh1.as_ref());
        hasher.update(dh2.as_ref());
        let ikm = hasher.finalize();
        K::kdf(
            ikm.as_ref(),
            self.pre_shared_key,
            "autograph/handshake/v1".as_bytes(),
            secret_key,
        );
    }
}

pub struct Channel<A: Aead, K: Kdf, const W: usize> {
    sending_key: A::SecretKey,
    receiving_key: A::SecretKey,
    receiving_window: ReceivingWindow<W>,
    _marker: PhantomData<(A, K)>,
}

impl<A: Aead, K: Kdf, const W: usize> Channel<A, K, W> {
    pub fn new(
        secret_key: &[u8],
        sending_context: &[u8],
        receiving_context: &[u8],
    ) -> Option<Self> {
        if sending_context == receiving_context {
            return None;
        }
        let mut sending_key = A::SecretKey::new();
        let mut receiving_key = A::SecretKey::new();
        K::kdf(secret_key, None, sending_context, sending_key.as_mut());
        K::kdf(secret_key, None, receiving_context, receiving_key.as_mut());
        Some(Self {
            sending_key,
            receiving_key,
            receiving_window: ReceivingWindow::<W>::new(),
            _marker: PhantomData,
        })
    }

    pub fn send(
        &self,
        nonce: &mut A::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
    ) -> Option<(u64, A::Tag)> {
        let index = A::increment_nonce(nonce)?;
        let tag = A::encrypt(&self.sending_key, nonce, aad, message);
        Some((index, tag))
    }

    pub fn receive(
        &mut self,
        nonce: &A::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
        tag: &A::Tag,
    ) -> Option<u64> {
        if A::decrypt(&self.receiving_key, nonce, aad, message, tag) {
            let index = A::read_index(nonce);
            if self.receiving_window.mark(index) {
                Some(index)
            } else {
                None
            }
        } else {
            None
        }
    }
}

struct ReceivingWindow<const W: usize> {
    top: u64,
    bitmap: [u64; W],
}

impl<const W: usize> ReceivingWindow<W> {
    const BITS: u64 = (W as u64).saturating_mul(64);

    fn new() -> Self {
        Self {
            top: 0,
            bitmap: [0u64; W],
        }
    }

    fn mark(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if self.top == 0 {
            self.top = counter;
            self.bitmap = [0u64; W];
            self.set_bit(counter);
            return true;
        }
        if counter.saturating_add(Self::BITS) <= self.top {
            return false;
        }
        if counter <= self.top {
            if self.is_set(counter) {
                return false;
            }
            self.set_bit(counter);
            return true;
        }
        let advance = counter - self.top;
        if advance >= Self::BITS {
            self.bitmap = [0u64; W];
        } else {
            for c in (self.top + 1)..counter {
                self.clear_bit(c);
            }
        }
        self.top = counter;
        self.set_bit(counter);
        true
    }

    fn slot(counter: u64) -> (usize, u64) {
        let bit = (counter % Self::BITS) as usize;
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        (word, mask)
    }

    fn clear_bit(&mut self, counter: u64) {
        let (word, mask) = Self::slot(counter);
        self.bitmap[word] &= !mask;
    }

    fn set_bit(&mut self, counter: u64) {
        let (word, mask) = Self::slot(counter);
        self.bitmap[word] |= mask;
    }

    fn is_set(&self, counter: u64) -> bool {
        let (word, mask) = Self::slot(counter);
        self.bitmap[word] & mask != 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use {
        super::{Aead, Csprng, Hasher, Kdf, KeyExchange, Signer},
        stedy::{
            aeads::ChaCha20Poly1305, csprngs::Rng, hashes::Sha512, kdfs::Hkdf,
            key_exchange::X25519, signatures::Ed25519,
        },
    };

    impl Aead for ChaCha20Poly1305 {
        type SecretKey = [u8; 32];
        type Nonce = [u8; 12];
        type Tag = [u8; 16];

        fn encrypt(
            key: &Self::SecretKey,
            nonce: &Self::Nonce,
            aad: Option<&[u8]>,
            message: &mut [u8],
        ) -> Self::Tag {
            Self::encrypt(key, nonce, aad, message)
        }

        fn decrypt(
            key: &Self::SecretKey,
            nonce: &Self::Nonce,
            aad: Option<&[u8]>,
            message: &mut [u8],
            tag: &Self::Tag,
        ) -> bool {
            Self::decrypt(key, nonce, aad, message, tag)
        }

        fn increment_nonce(nonce: &mut Self::Nonce) -> Option<u64> {
            let mut index = Self::read_index(nonce);
            if index == u64::MAX {
                return None;
            }
            index += 1;
            let (dest, _) = nonce.as_mut().split_at_mut_checked(8)?;
            dest.copy_from_slice(&index.to_le_bytes());
            Some(index)
        }

        fn read_index(nonce: &Self::Nonce) -> u64 {
            let (slice, _) = nonce.as_ref().split_at(8);
            let src = <&[u8; 8]>::try_from(slice).unwrap();
            u64::from_le_bytes(*src)
        }
    }

    impl Csprng for Rng {
        fn fill(&mut self, bytes: &mut [u8]) {
            self.fill(bytes);
        }
    }

    impl KeyExchange for X25519 {
        type PrivateKey = [u8; 32];
        type PublicKey = [u8; 32];
        type SharedSecret = [u8; 32];

        fn generate_key_pair(csprng: &mut impl Csprng) -> (Self::PrivateKey, Self::PublicKey) {
            let mut private_key = [0u8; 32];
            csprng.fill(private_key.as_mut());
            let public_key = Self::public_key(&private_key).unwrap();
            (private_key, public_key)
        }

        fn key_exchange(
            private_key: &Self::PrivateKey,
            public_key: &Self::PublicKey,
        ) -> Self::SharedSecret {
            Self::key_exchange(private_key, public_key).unwrap()
        }
    }

    impl Hasher for Sha512 {
        type Digest = [u8; 64];

        fn new() -> Self {
            Self::new()
        }

        fn update(&mut self, message: &[u8]) {
            self.update(message);
        }

        fn finalize(self) -> Self::Digest {
            self.finalize()
        }
    }

    impl Kdf for Hkdf<Sha512> {
        fn kdf(ikm: &[u8], salt: Option<&[u8]>, context: &[u8], okm: &mut [u8]) {
            Self::hkdf(ikm, salt, Some(context), okm);
        }
    }

    struct Ed25519Signer {
        private_key: <Self as Signer>::PrivateKey,
        public_key: <Self as Signer>::PublicKey,
    }

    impl From<[u8; 32]> for Ed25519Signer {
        fn from(private_key: [u8; 32]) -> Self {
            let public_key = Ed25519::public_key(&private_key);
            Self {
                private_key,
                public_key,
            }
        }
    }

    impl Signer for Ed25519Signer {
        type PrivateKey = [u8; 32];
        type PublicKey = [u8; 32];
        type Signature = [u8; 64];

        fn public_key(&self) -> Option<Self::PublicKey> {
            Some(self.public_key)
        }

        fn sign(&self, subject: &[u8]) -> Option<Self::Signature> {
            Some(Ed25519::sign(&self.private_key, subject))
        }

        fn verify(
            subject: &[u8],
            public_key: &Self::PublicKey,
            signature: &Self::Signature,
        ) -> bool {
            Ed25519::verify(subject, public_key, signature)
        }
    }

    type Credential = super::Credential<Sha512, Ed25519Signer>;
    type Handshake<'a> = super::Handshake<'a, X25519, Sha512, Hkdf<Sha512>, Ed25519Signer>;
    type Channel<const W: usize> = super::Channel<ChaCha20Poly1305, Hkdf<Sha512>, W>;

    const ALICE_IDENTITY_PRIVATE_KEY: [u8; 32] = [
        67, 201, 60, 206, 157, 93, 211, 96, 218, 86, 91, 65, 153, 204, 246, 45, 29, 32, 69, 14,
        174, 196, 114, 247, 152, 186, 84, 142, 184, 155, 212, 4,
    ];
    const ALICE_IDENTITY_PUBLIC_KEY: [u8; 32] = [
        76, 215, 85, 125, 180, 19, 183, 9, 70, 18, 170, 68, 72, 208, 3, 142, 20, 94, 115, 188, 120,
        143, 243, 226, 205, 146, 51, 135, 203, 238, 18, 90,
    ];
    const ALICE_PRIVATE_KEY: [u8; 32] = [
        16, 204, 77, 236, 130, 65, 36, 15, 214, 229, 148, 82, 70, 249, 129, 39, 189, 169, 231, 57,
        217, 1, 65, 253, 223, 206, 9, 15, 16, 185, 200, 11,
    ];
    const ALICE_PUBLIC_KEY: [u8; 32] = [
        97, 255, 193, 254, 153, 139, 199, 109, 61, 189, 1, 113, 229, 156, 176, 168, 246, 53, 137,
        158, 171, 199, 79, 15, 69, 156, 87, 254, 251, 88, 110, 0,
    ];
    const ALICE_ID: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    const CLAIM_DATA: [u8; 32] = [
        97, 255, 193, 254, 153, 139, 199, 109, 61, 189, 1, 113, 229, 156, 176, 168, 246, 53, 137,
        158, 171, 199, 79, 15, 69, 156, 87, 254, 251, 88, 110, 0,
    ];
    const CLAIM_SIGNATURE: [u8; 64] = [
        28, 47, 2, 104, 159, 98, 95, 202, 30, 107, 227, 173, 90, 118, 137, 230, 42, 35, 224, 129,
        99, 27, 191, 67, 146, 78, 46, 34, 95, 129, 148, 138, 243, 154, 100, 65, 39, 206, 189, 98,
        207, 71, 101, 194, 1, 131, 190, 88, 43, 110, 119, 253, 127, 161, 17, 151, 47, 18, 63, 163,
        118, 3, 18, 4,
    ];
    const BOB_IDENTITY_PRIVATE_KEY: [u8; 32] = [
        149, 47, 129, 35, 29, 130, 113, 127, 151, 34, 196, 152, 245, 26, 16, 238, 15, 160, 70, 157,
        1, 65, 192, 136, 74, 51, 196, 25, 58, 235, 72, 20,
    ];
    const BOB_IDENTITY_PUBLIC_KEY: [u8; 32] = [
        111, 137, 26, 242, 69, 130, 112, 197, 26, 187, 0, 68, 97, 212, 40, 42, 157, 88, 214, 107,
        62, 136, 115, 158, 170, 56, 13, 252, 221, 194, 172, 235,
    ];
    const BOB_PRIVATE_KEY: [u8; 32] = [
        68, 219, 154, 89, 27, 45, 28, 126, 123, 170, 62, 44, 184, 155, 107, 166, 53, 180, 220, 90,
        71, 71, 213, 181, 99, 91, 217, 122, 18, 6, 125, 197,
    ];
    const BOB_PUBLIC_KEY: [u8; 32] = [
        132, 179, 251, 109, 54, 41, 110, 149, 90, 220, 140, 188, 68, 42, 105, 58, 11, 210, 105,
        213, 183, 182, 170, 182, 28, 220, 173, 127, 17, 248, 101, 99,
    ];
    const BOB_ID: [u8; 10] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
    const CHARLIE_IDENTITY_PRIVATE_KEY: [u8; 32] = [
        5, 199, 6, 227, 85, 3, 31, 15, 149, 103, 247, 180, 126, 254, 241, 130, 66, 118, 182, 214,
        250, 206, 75, 69, 242, 198, 239, 71, 214, 7, 51, 113,
    ];
    const CHARLIE_IDENTITY_PUBLIC_KEY: [u8; 32] = [
        132, 29, 178, 80, 226, 221, 83, 185, 253, 213, 16, 93, 229, 241, 253, 24, 184, 1, 117, 98,
        246, 22, 247, 171, 3, 201, 126, 227, 86, 31, 104, 140,
    ];
    const ENDORSEMENT_DATA: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    const ENDORSEMENT_SIGNATURE: [u8; 64] = [
        120, 19, 186, 213, 177, 162, 149, 221, 21, 176, 174, 121, 132, 68, 158, 10, 36, 12, 141,
        228, 129, 20, 111, 251, 119, 56, 57, 98, 206, 187, 55, 163, 113, 226, 87, 33, 136, 14, 152,
        127, 45, 134, 3, 185, 68, 191, 10, 88, 151, 223, 239, 116, 249, 131, 243, 31, 229, 142, 4,
        137, 168, 200, 172, 0,
    ];
    const SECRET_KEY: [u8; 32] = [
        165, 1, 148, 204, 26, 115, 198, 118, 153, 67, 27, 81, 51, 81, 3, 93, 192, 32, 243, 175, 13,
        71, 43, 224, 48, 232, 252, 107, 153, 247, 244, 72,
    ];

    #[test]
    fn test_claim() {
        let signer = Ed25519Signer::from(ALICE_IDENTITY_PRIVATE_KEY);
        let signature = Credential::claim(&signer, &CLAIM_DATA).unwrap();
        assert_eq!(signature, CLAIM_SIGNATURE);
    }

    #[test]
    fn test_endorse() {
        let signer = Ed25519Signer::from(CHARLIE_IDENTITY_PRIVATE_KEY);
        let signature = Credential::endorse(
            &signer,
            Some(&ENDORSEMENT_DATA),
            &ALICE_IDENTITY_PUBLIC_KEY,
            &CLAIM_DATA,
            &CLAIM_SIGNATURE,
        )
        .unwrap();
        assert_eq!(signature, ENDORSEMENT_SIGNATURE);
    }

    #[test]
    fn test_verify() {
        let signer = Ed25519Signer::from(ALICE_IDENTITY_PRIVATE_KEY);
        let mut rng = Rng::seed();
        let mut challenge = [0u8; 32];
        Credential::generate_challenge(&mut rng, &mut challenge);
        let presentation_signature = Credential::present(&signer, &CLAIM_DATA, &challenge).unwrap();
        let verified = Credential::verify(
            &challenge,
            &ALICE_IDENTITY_PUBLIC_KEY,
            &CLAIM_DATA,
            &presentation_signature,
            &CHARLIE_IDENTITY_PUBLIC_KEY,
            Some(&ENDORSEMENT_DATA),
            &ENDORSEMENT_SIGNATURE,
        );
        assert!(verified);
    }

    #[test]
    fn test_generate_key_pair() {
        let mut rng = Rng::seed();
        let key_pair = Handshake::generate_key_pair(&mut rng);
        assert_ne!(key_pair, ([0u8; 32], [0u8; 32]));
    }

    #[test]
    fn test_handshake() {
        let alice_signer = Ed25519Signer::from(ALICE_IDENTITY_PRIVATE_KEY);
        let bob_signer = Ed25519Signer::from(BOB_IDENTITY_PRIVATE_KEY);
        let mut rng = Rng::seed();
        let (alice_ephemeral_private_key, alice_ephemeral_public_key) =
            Handshake::generate_key_pair(&mut rng);
        let (bob_ephemeral_private_key, bob_ephemeral_public_key) =
            Handshake::generate_key_pair(&mut rng);
        let alice = Handshake::new(
            &ALICE_PRIVATE_KEY,
            &ALICE_PUBLIC_KEY,
            &alice_ephemeral_private_key,
            &alice_ephemeral_public_key,
            Some(&SECRET_KEY),
        );
        let bob = Handshake::new(
            &BOB_PRIVATE_KEY,
            &BOB_PUBLIC_KEY,
            &bob_ephemeral_private_key,
            &bob_ephemeral_public_key,
            Some(&SECRET_KEY),
        );
        let alice_auth = alice
            .authenticate(
                &alice_signer,
                &ALICE_ID,
                &BOB_IDENTITY_PUBLIC_KEY,
                &BOB_PUBLIC_KEY,
                &BOB_ID,
            )
            .unwrap();
        let bob_auth = bob
            .authenticate(
                &bob_signer,
                &BOB_ID,
                &ALICE_IDENTITY_PUBLIC_KEY,
                &ALICE_PUBLIC_KEY,
                &ALICE_ID,
            )
            .unwrap();
        let bob_signature = bob.certify(&bob_signer).unwrap();
        let mut alice_secret_key = [0u8; 32];
        let mut bob_secret_key = [0u8; 32];
        let alice_signature = alice
            .initiator(
                &alice_signer,
                &BOB_IDENTITY_PUBLIC_KEY,
                &BOB_PUBLIC_KEY,
                &bob_ephemeral_public_key,
                &bob_signature,
                &mut alice_secret_key,
            )
            .unwrap();
        let verified = bob.responder(
            &ALICE_IDENTITY_PUBLIC_KEY,
            &ALICE_PUBLIC_KEY,
            &alice_ephemeral_public_key,
            &alice_signature,
            &mut bob_secret_key,
        );
        assert_eq!(
            alice_auth,
            [
                0, 186, 199, 49, 72, 167, 3, 71, 116, 16, 25, 171, 216, 47, 68, 36, 26, 40, 198,
                158, 90, 24, 16, 184, 101, 138, 109, 12, 116, 104, 161, 141, 231, 130, 138, 31,
                220, 101, 154, 57, 78, 162, 244, 179, 34, 72, 8, 114, 185, 129, 157, 131, 47, 122,
                92, 22, 77, 95, 144, 175, 115, 241, 218, 97
            ]
        );
        assert_eq!(alice_auth, bob_auth);
        assert!(verified);
        assert_ne!(alice_secret_key, [0u8; 32]);
        assert_eq!(alice_secret_key, bob_secret_key)
    }

    #[test]
    fn test_channel_send() {
        let mut nonce = [0u8; 12];
        let mut message = [
            97, 255, 193, 254, 153, 139, 199, 109, 61, 189, 1, 113, 229, 156, 176, 168, 246, 53,
            137, 158, 171, 199, 79, 15, 69, 156, 87, 254, 251, 88, 110, 0,
        ];
        let a = Channel::<1>::new(
            &SECRET_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
        )
        .unwrap();
        let mut b = Channel::<2>::new(
            &SECRET_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
        )
        .unwrap();
        let (index, tag) = a.send(&mut nonce, None, &mut message).unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            tag,
            [
                46, 105, 140, 232, 225, 193, 69, 214, 241, 241, 226, 165, 250, 93, 232, 159
            ],
        );
        assert_eq!(nonce, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            message,
            [
                182, 212, 230, 162, 168, 195, 22, 242, 46, 124, 207, 163, 80, 28, 47, 34, 215, 183,
                130, 175, 46, 131, 226, 179, 100, 243, 246, 45, 136, 197, 58, 184
            ]
        );
        let index = b.receive(&nonce, None, &mut message, &tag).unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            message,
            [
                97, 255, 193, 254, 153, 139, 199, 109, 61, 189, 1, 113, 229, 156, 176, 168, 246,
                53, 137, 158, 171, 199, 79, 15, 69, 156, 87, 254, 251, 88, 110, 0,
            ],
        );
    }

    #[test]
    fn test_channel_replay() {
        let mut channel = Channel::<1>::new(
            &SECRET_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
        )
        .unwrap();
        const NONCE: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        const TAG: [u8; 16] = [
            46, 105, 140, 232, 225, 193, 69, 214, 241, 241, 226, 165, 250, 93, 232, 159,
        ];
        let mut message1 = [
            182, 212, 230, 162, 168, 195, 22, 242, 46, 124, 207, 163, 80, 28, 47, 34, 215, 183,
            130, 175, 46, 131, 226, 179, 100, 243, 246, 45, 136, 197, 58, 184,
        ];
        let mut message2 = message1.clone();
        let result = channel.receive(&NONCE, None, &mut message1, &TAG);
        assert!(result.is_some());
        let result = channel.receive(&NONCE, None, &mut message2, &TAG);
        assert!(result.is_none());
    }
}
