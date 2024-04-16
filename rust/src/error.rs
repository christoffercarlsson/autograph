#[derive(Debug)]
pub enum Error {
    Authentication,
    Certification,
    ChannelUnestablished,
    Decryption,
    Encryption,
    SkipIndex,
    KeyExchange,
    KeyExchangeVerification,
    KeyPair,
    Nonce,
    Padding,
}
