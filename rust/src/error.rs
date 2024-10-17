#[derive(Debug)]
pub enum Error {
    Authentication,
    Certification,
    Decryption,
    Encryption,
    KeyExchange,
    KeyGeneration,
    KeyPair,
}
