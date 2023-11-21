#[derive(Debug)]
pub enum Error {
    ChannelAlreadyEstablished,
    ChannelAlreadyInitialized,
    ChannelUnestablished,
    ChannelUninitialized,
    Decryption,
    Encryption,
    Initialization,
    KeyExchange,
    KeyExchangeVerification,
    KeyPairGeneration,
    SafetyNumberCalculation,
    Signing,
}
