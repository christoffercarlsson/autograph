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

pub trait Digest {
    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;
}

pub trait Hasher: Digest {
    fn new() -> Self;
}

pub trait Mac: Digest {
    fn new(key: &[u8]) -> Option<Self>
    where
        Self: Sized;

    fn verify(self, code: &Self::Output) -> bool;
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
