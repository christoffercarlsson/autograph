#![no_std]
#![deny(clippy::unwrap_used)]

mod channel;
mod credential;
mod handshake;
mod primitives;

pub use {
    channel::Channel,
    credential::Credential,
    handshake::{Authenticator, Certificate, Handshake},
    primitives::{Aead, Csprng, Digest, Hasher, Kdf, KeyExchange, Mac, Signer},
};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use {
        super::{Aead, Csprng, Digest, Hasher, Kdf, KeyExchange, Mac, Signer},
        stedy::{
            aeads::ChaCha20Poly1305, csprngs::Rng, hashes::Sha512, kdfs::Hkdf,
            key_exchange::X25519, macs::Hmac, signatures::Ed25519,
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

    impl Digest for Sha512 {
        type Output = [u8; 64];

        fn update(&mut self, message: &[u8]) {
            self.update(&(message.len() as u64).to_le_bytes());
            self.update(message);
        }

        fn finalize(self) -> Self::Output {
            self.finalize()
        }
    }

    impl Hasher for Sha512 {
        fn new() -> Self {
            Self::new()
        }
    }

    impl Digest for Hmac<Sha512> {
        type Output = [u8; 64];

        fn update(&mut self, message: &[u8]) {
            self.update(&(message.len() as u64).to_le_bytes());
            self.update(message);
        }

        fn finalize(self) -> Self::Output {
            self.finalize()
        }
    }

    impl Mac for Hmac<Sha512> {
        fn new(key: &[u8]) -> Option<Self> {
            Some(Self::new(key))
        }

        fn verify(self, code: &Self::Output) -> bool {
            self.verify(code)
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
    type Handshake<'a> = super::Handshake<
        'a,
        ChaCha20Poly1305,
        X25519,
        Sha512,
        Hkdf<Sha512>,
        Hmac<Sha512>,
        Ed25519Signer,
        1,
    >;
    type Certificate = super::Certificate<X25519, Ed25519Signer>;
    type Channel = super::Channel<ChaCha20Poly1305, Hkdf<Sha512>, 1>;

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
        107, 229, 251, 183, 13, 231, 11, 94, 165, 55, 90, 163, 71, 236, 209, 5, 223, 246, 78, 251,
        68, 42, 215, 2, 91, 56, 37, 23, 16, 200, 72, 157, 211, 166, 195, 65, 40, 219, 61, 196, 64,
        205, 117, 135, 1, 171, 168, 2, 126, 82, 211, 49, 183, 160, 162, 12, 177, 77, 100, 146, 222,
        147, 170, 9,
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
        173, 0, 167, 37, 159, 153, 74, 69, 107, 194, 87, 95, 174, 17, 38, 37, 194, 235, 31, 148,
        180, 67, 125, 229, 14, 76, 136, 219, 70, 109, 224, 226, 45, 36, 94, 232, 215, 125, 221,
        195, 198, 251, 252, 195, 36, 110, 100, 250, 148, 10, 193, 127, 225, 243, 221, 103, 0, 223,
        206, 100, 170, 207, 119, 10,
    ];
    const SECRET_KEY: [u8; 32] = [
        165, 1, 148, 204, 26, 115, 198, 118, 153, 67, 27, 81, 51, 81, 3, 93, 192, 32, 243, 175, 13,
        71, 43, 224, 48, 232, 252, 107, 153, 247, 244, 72,
    ];

    #[test]
    fn test_authenticate() {
        let alice = Ed25519Signer::from(ALICE_IDENTITY_PRIVATE_KEY);
        let bob = Ed25519Signer::from(BOB_IDENTITY_PRIVATE_KEY);
        let mut a = Credential::authenticate(&alice, &BOB_IDENTITY_PUBLIC_KEY).unwrap();
        let mut b = Credential::authenticate(&bob, &ALICE_IDENTITY_PUBLIC_KEY).unwrap();
        for hasher in [&mut a, &mut b] {
            hasher.update(&BOB_ID);
            hasher.update(&ALICE_ID);
        }
        let a = a.finalize();
        let b = b.finalize();
        assert_eq!(
            a,
            [
                40, 247, 253, 4, 252, 92, 71, 112, 185, 246, 36, 232, 113, 38, 52, 98, 143, 190,
                135, 224, 249, 195, 216, 36, 48, 200, 193, 188, 28, 238, 11, 230, 243, 192, 83, 97,
                13, 236, 66, 95, 189, 118, 226, 187, 9, 10, 48, 238, 65, 254, 170, 82, 208, 207,
                183, 235, 32, 73, 127, 141, 249, 241, 195, 130
            ]
        );
        assert_eq!(a, b);
    }

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
    fn test_certificate() {
        let bob = Handshake::new(&BOB_PRIVATE_KEY, &BOB_PUBLIC_KEY);
        let bob_signer = Ed25519Signer::from(BOB_IDENTITY_PRIVATE_KEY);
        let certificate = bob.certify(&bob_signer).unwrap();
        assert_eq!(Certificate::SIZE, 128);
        let mut buffer = [0u8; Certificate::SIZE + 8];
        let mut bytes = [0u8; Certificate::SIZE];
        let serialized = certificate.serialize(&mut buffer).unwrap();
        assert_eq!(serialized.len(), Certificate::SIZE);
        bytes.copy_from_slice(serialized);
        let restored: Certificate = bytes.as_ref().try_into().unwrap();
        assert_eq!(restored.identity_key(), certificate.identity_key());
        assert_eq!(restored.public_key(), certificate.public_key());
        assert_eq!(restored.signature(), certificate.signature());
        let mut short = [0u8; 8];
        assert!(certificate.serialize(&mut short).is_none());
        assert!(Certificate::try_from(short.as_ref()).is_err());
        let alice = Handshake::new(&ALICE_PRIVATE_KEY, &ALICE_PUBLIC_KEY);
        let mut secret_key = [0u8; 32];
        let mut session_key = [0u8; 32];
        assert!(
            alice
                .initiator(&restored, None, &mut secret_key, &mut session_key)
                .is_some()
        );
    }

    #[test]
    fn test_handshake() {
        let alice = Handshake::new(&ALICE_PRIVATE_KEY, &ALICE_PUBLIC_KEY);
        let bob = Handshake::new(&BOB_PRIVATE_KEY, &BOB_PUBLIC_KEY);
        let bob_signer = Ed25519Signer::from(BOB_IDENTITY_PRIVATE_KEY);
        let certificate = bob.certify(&bob_signer).unwrap();
        let mut alice_secret_key = [0u8; 32];
        let mut alice_session_key = [0u8; 32];
        let mut bob_secret_key = [0u8; 32];
        let mut bob_session_key = [0u8; 32];
        let (a, mut alice_authenticator) = alice
            .initiator(
                &certificate,
                Some(&SECRET_KEY),
                &mut alice_secret_key,
                &mut alice_session_key,
            )
            .unwrap();
        let (mut b, mut bob_authenticator) = bob
            .responder(
                &bob_signer,
                &ALICE_PUBLIC_KEY,
                Some(&SECRET_KEY),
                &mut bob_secret_key,
                &mut bob_session_key,
            )
            .unwrap();
        for authenticator in [&mut alice_authenticator, &mut bob_authenticator] {
            authenticator.update(&BOB_ID);
            authenticator.update(&ALICE_ID);
        }
        let alice_mac = alice_authenticator.code();
        let bob_mac = bob_authenticator.code();
        let alice_auth = alice_authenticator.authenticate();
        let bob_auth = bob_authenticator.authenticate();
        assert_eq!(
            alice_authenticator.authenticate(),
            bob_authenticator.authenticate()
        );
        assert_ne!(alice_auth, alice_mac);
        assert_ne!(bob_auth, bob_mac);
        assert!(bob_authenticator.verify(&alice_mac));
        assert!(alice_authenticator.verify(&bob_mac));
        assert_eq!(
            alice_mac,
            [
                118, 49, 242, 208, 93, 89, 164, 76, 189, 86, 195, 73, 210, 191, 112, 251, 73, 74,
                197, 73, 183, 181, 87, 193, 253, 4, 167, 223, 255, 156, 207, 37, 93, 160, 209, 83,
                79, 127, 169, 88, 106, 73, 1, 58, 255, 103, 195, 134, 163, 179, 153, 149, 104, 241,
                29, 8, 49, 211, 195, 245, 106, 236, 116, 208
            ]
        );
        assert_eq!(
            bob_mac,
            [
                233, 12, 178, 104, 231, 125, 98, 50, 169, 218, 188, 123, 53, 83, 34, 135, 27, 53,
                30, 246, 9, 63, 32, 111, 76, 187, 117, 133, 148, 164, 123, 248, 184, 218, 188, 152,
                238, 62, 124, 16, 74, 228, 172, 248, 251, 213, 63, 250, 51, 81, 119, 77, 47, 101,
                99, 152, 205, 245, 186, 225, 227, 246, 220, 18
            ]
        );
        assert_eq!(
            alice_secret_key,
            [
                95, 54, 62, 231, 35, 29, 73, 102, 30, 113, 51, 226, 251, 11, 175, 242, 121, 42,
                170, 165, 117, 44, 34, 48, 230, 108, 72, 186, 145, 114, 45, 139
            ]
        );
        assert_eq!(
            alice_session_key,
            [
                65, 75, 247, 216, 134, 223, 45, 121, 234, 50, 94, 17, 94, 176, 207, 21, 193, 82,
                238, 131, 103, 29, 160, 130, 95, 206, 234, 112, 39, 234, 202, 14
            ]
        );
        assert_eq!(alice_secret_key, bob_secret_key);
        assert_eq!(alice_session_key, bob_session_key);
        let mut nonce = [0u8; 12];
        let mut message = [
            97, 255, 193, 254, 153, 139, 199, 109, 61, 189, 1, 113, 229, 156, 176, 168, 246, 53,
            137, 158, 171, 199, 79, 15, 69, 156, 87, 254, 251, 88, 110, 0,
        ];
        let (index, tag) = a.send(&mut nonce, None, &mut message).unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            tag,
            [
                209, 18, 67, 60, 108, 14, 16, 33, 82, 232, 246, 121, 184, 151, 121, 253
            ],
        );
        assert_eq!(nonce, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            message,
            [
                34, 67, 99, 202, 136, 213, 231, 153, 67, 32, 17, 199, 85, 135, 17, 129, 204, 13,
                127, 197, 32, 141, 235, 41, 156, 119, 16, 31, 109, 232, 224, 84
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
    fn test_channel_send() {
        let mut nonce = [0u8; 12];
        let mut message = [
            97, 255, 193, 254, 153, 139, 199, 109, 61, 189, 1, 113, 229, 156, 176, 168, 246, 53,
            137, 158, 171, 199, 79, 15, 69, 156, 87, 254, 251, 88, 110, 0,
        ];
        let a = Channel::new(
            &SECRET_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
        )
        .unwrap();
        let mut b = Channel::new(
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
        let mut channel = Channel::new(
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
        let mut message2 = message1;
        let result = channel.receive(&NONCE, None, &mut message1, &TAG);
        assert!(result.is_some());
        let result = channel.receive(&NONCE, None, &mut message2, &TAG);
        assert!(result.is_none());
    }

    #[test]
    fn test_channel_close_open() {
        const NONCE: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        const TAG: [u8; 16] = [
            46, 105, 140, 232, 225, 193, 69, 214, 241, 241, 226, 165, 250, 93, 232, 159,
        ];
        let mut message = [
            182, 212, 230, 162, 168, 195, 22, 242, 46, 124, 207, 163, 80, 28, 47, 34, 215, 183,
            130, 175, 46, 131, 226, 179, 100, 243, 246, 45, 136, 197, 58, 184,
        ];
        let mut channel = Channel::new(
            &SECRET_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
        )
        .unwrap();
        assert!(channel.receive(&NONCE, None, &mut message, &TAG).is_some());
        let mut buffer = [0u8; Channel::SIZE + 7];
        let state = channel.close(&NONCE, &mut buffer).unwrap();
        assert_eq!(state.len(), Channel::SIZE);
        let (mut channel, nonce) = Channel::open(
            &SECRET_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
            &buffer,
        )
        .unwrap();
        assert_eq!(nonce, NONCE);
        let mut replay = [
            182, 212, 230, 162, 168, 195, 22, 242, 46, 124, 207, 163, 80, 28, 47, 34, 215, 183,
            130, 175, 46, 131, 226, 179, 100, 243, 246, 45, 136, 197, 58, 184,
        ];
        assert!(channel.receive(&nonce, None, &mut replay, &TAG).is_none());
        let mut short = [0u8; 8];
        assert!(
            Channel::open(
                &SECRET_KEY,
                &BOB_IDENTITY_PUBLIC_KEY,
                &ALICE_IDENTITY_PUBLIC_KEY,
                &short
            )
            .is_none()
        );
        let (channel, nonce) = Channel::open(
            &SECRET_KEY,
            &BOB_IDENTITY_PUBLIC_KEY,
            &ALICE_IDENTITY_PUBLIC_KEY,
            &buffer,
        )
        .unwrap();
        assert!(channel.close(&nonce, &mut short).is_none());
    }
}
