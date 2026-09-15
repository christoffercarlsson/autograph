#![no_std]
#![deny(clippy::unwrap_used)]

mod channel;
mod credential;
mod handshake;
mod primitives;

pub use {
    channel::Channel,
    credential::Credential,
    handshake::Handshake,
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
        81, 139, 147, 5, 140, 137, 220, 252, 125, 50, 131, 84, 157, 178, 158, 126, 177, 221, 1, 44,
        91, 115, 43, 21, 182, 177, 70, 150, 182, 110, 93, 102, 161, 56, 23, 236, 168, 159, 8, 42,
        145, 64, 26, 127, 56, 212, 190, 159, 44, 98, 174, 196, 25, 214, 151, 74, 91, 95, 218, 183,
        82, 214, 13, 10,
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
        169, 100, 118, 119, 181, 175, 52, 145, 64, 65, 244, 233, 172, 42, 154, 22, 57, 251, 199,
        95, 251, 39, 239, 99, 57, 176, 164, 66, 219, 26, 174, 211, 249, 79, 199, 70, 165, 113, 215,
        71, 28, 207, 113, 123, 225, 178, 11, 222, 56, 31, 162, 136, 162, 240, 162, 122, 19, 22,
        244, 177, 140, 102, 255, 15,
    ];
    const SECRET_KEY: [u8; 32] = [
        165, 1, 148, 204, 26, 115, 198, 118, 153, 67, 27, 81, 51, 81, 3, 93, 192, 32, 243, 175, 13,
        71, 43, 224, 48, 232, 252, 107, 153, 247, 244, 72,
    ];
    
    #[test]
    fn test_authenticate() {
        let alice = Ed25519Signer::from(ALICE_IDENTITY_PRIVATE_KEY);
        let bob = Ed25519Signer::from(BOB_IDENTITY_PRIVATE_KEY);
        let a = Credential::authenticate(&alice, &BOB_IDENTITY_PUBLIC_KEY).unwrap();
        let b = Credential::authenticate(&bob, &ALICE_IDENTITY_PUBLIC_KEY).unwrap();
        assert_ne!(a, [0u8; 64]);
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
    fn test_handshake() {
        let alice = Handshake::new(&ALICE_PRIVATE_KEY, &ALICE_PUBLIC_KEY);
        let bob = Handshake::new(&BOB_PRIVATE_KEY, &BOB_PUBLIC_KEY);
        let bob_signer = Ed25519Signer::from(BOB_IDENTITY_PRIVATE_KEY);
        let (bob_identity_key, bob_signature) = bob.certify(&bob_signer).unwrap();
        let mut alice_secret_key = [0u8; 32];
        let mut alice_session_key = [0u8; 32];
        let mut bob_secret_key = [0u8; 32];
        let mut bob_session_key = [0u8; 32];
        let (a, mut alice_mac) = alice
            .initiator(
                &bob_identity_key,
                &BOB_PUBLIC_KEY,
                &bob_signature,
                Some(&SECRET_KEY),
                &mut alice_secret_key,
                &mut alice_session_key,
            )
            .unwrap();
        let (mut b, mut bob_mac) = bob
            .responder(
                &bob_signer,
                &ALICE_PUBLIC_KEY,
                Some(&SECRET_KEY),
                &mut bob_secret_key,
                &mut bob_session_key,
            )
            .unwrap();
        alice_mac.update(&BOB_ID);
        alice_mac.update(&ALICE_ID);
        bob_mac.update(&BOB_ID);
        bob_mac.update(&ALICE_ID);
        let code = bob_mac.finalize();
        let verified = alice_mac.verify(&code);
        assert!(verified);
        assert_eq!(
            code,
            [
                13, 87, 1, 182, 96, 217, 172, 243, 98, 60, 60, 241, 122, 198, 38, 112, 214, 149,
                72, 84, 73, 33, 217, 210, 85, 152, 14, 246, 79, 63, 33, 32, 62, 45, 153, 209, 41,
                172, 194, 57, 58, 170, 24, 10, 164, 236, 167, 67, 87, 225, 217, 3, 81, 93, 85, 208,
                152, 169, 25, 85, 0, 115, 68, 231
            ]
        );
        assert_eq!(
            alice_secret_key,
            [
                209, 209, 49, 217, 113, 50, 50, 164, 169, 66, 3, 162, 98, 186, 82, 96, 94, 224,
                211, 187, 90, 248, 89, 166, 90, 154, 78, 133, 127, 47, 95, 74
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
        let mut message2 = message1.clone();
        let result = channel.receive(&NONCE, None, &mut message1, &TAG);
        assert!(result.is_some());
        let result = channel.receive(&NONCE, None, &mut message2, &TAG);
        assert!(result.is_none());
    }
}
