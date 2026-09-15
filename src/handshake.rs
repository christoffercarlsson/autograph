use {
    crate::{
        channel::Channel,
        primitives::{Aead, Mac, Csprng, Hasher, Kdf, KeyExchange, Signer},
    },
    core::marker::PhantomData,
};

pub struct Handshake<'a, A: Aead, D: KeyExchange, H: Hasher, K: Kdf, M: Mac, S: Signer, const W: usize> {
    private_key: &'a D::PrivateKey,
    public_key: &'a D::PublicKey,
    _marker: PhantomData<(A, H, K, M, S)>,
}

static AUTHENTICATION_CONTEXT: &[u8; 22] = b"autograph/handshake/v1";
static CERTIFICATION_CONTEXT: &[u8; 20] = b"autograph/certify/v1";
static KEY_EXCHANGE_CONTEXT: &[u8; 25] = b"autograph/key-exchange/v1";
static SESSION_CONTEXT: &[u8; 20] = b"autograph/session/v1";

impl<'a, A: Aead, D: KeyExchange, H: Hasher, K: Kdf, M:Mac, S: Signer, const W: usize>
    Handshake<'a, A, D, H, K, M, S, W>
{
    pub fn new(private_key: &'a D::PrivateKey, public_key: &'a D::PublicKey) -> Self {
        Self {
            private_key,
            public_key,
            _marker: PhantomData,
        }
    }

    pub fn generate_key_pair(csprng: &mut impl Csprng) -> (D::PrivateKey, D::PublicKey) {
        D::generate_key_pair(csprng)
    }

    pub fn certify(&self, signer: &S) -> Option<(S::PublicKey, S::Signature)> {
        let identity_key = signer.public_key()?;
        let subject = Self::certification_subject(self.public_key);
        let signature = signer.sign(subject.as_ref())?;
        Some((identity_key, signature))
    }

    fn certification_subject(public_key: &D::PublicKey) -> H::Output {
        let mut hasher = H::new();
        hasher.update(CERTIFICATION_CONTEXT);
        hasher.update(public_key.as_ref());
        hasher.finalize()
    }

    pub fn establish(
        &self,
        their_public_key: &D::PublicKey,
        pre_shared_key: Option<&[u8]>,
        secret_key: &mut [u8],
        session_key: &mut [u8],
    ) -> Option<Channel<A, K, W>> {
        let ikm = D::key_exchange(self.private_key, their_public_key);
        K::kdf(ikm.as_ref(), pre_shared_key, KEY_EXCHANGE_CONTEXT, secret_key);
        K::kdf(
            ikm.as_ref(),
            pre_shared_key,
            SESSION_CONTEXT,
            session_key,
        );
        Channel::<A, K, W>::new(
            session_key,
            self.public_key.as_ref(),
            their_public_key.as_ref(),
        )
    }
    
    pub fn initiator(
        &self,
        their_identity_key: &S::PublicKey,
        their_public_key: &D::PublicKey,
        their_signature: &S::Signature,
        pre_shared_key: Option<&[u8]>,
        secret_key: &mut [u8],
        session_key: &mut [u8],
    ) -> Option<(Channel<A, K, W>, M)> {
        let subject = Self::certification_subject(their_public_key);
        if !S::verify(subject.as_ref(), their_identity_key, their_signature) {
            return None;
        }
        let channel = self.establish(their_public_key, pre_shared_key, secret_key, session_key)?;
        let mac = Self::authenticate(session_key, their_identity_key, self.public_key)?;
        Some((channel, mac))
    }
    
    pub fn responder(
        &self,
        signer: &S,
        their_public_key: &D::PublicKey,
        pre_shared_key: Option<&[u8]>,
        secret_key: &mut [u8],
        session_key: &mut [u8],
    ) -> Option<(Channel<A, K, W>, M)> {
        let identity_key = signer.public_key()?;
        let channel = self.establish(their_public_key, pre_shared_key, secret_key, session_key)?;
        let mac = Self::authenticate(session_key, &identity_key, their_public_key)?;
        Some((channel, mac))
    }

    fn authenticate(
        session_key: &[u8],
        responder_identity_key: &S::PublicKey,
        initiator_public_key: &D::PublicKey,
    ) -> Option<M> {
        let mut mac = M::new(session_key)?;
        mac.update(AUTHENTICATION_CONTEXT);
        mac.update(responder_identity_key.as_ref());
        mac.update(initiator_public_key.as_ref());
        Some(mac)
    }
}
