#[derive(Debug)]
pub enum Error {
    Authentication,
    Certification,
    Decryption,
    Encryption,
    KeyExchange,
    KeyPair,
}
