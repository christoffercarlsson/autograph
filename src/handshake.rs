use {
    crate::{
        channel::Channel,
        primitives::{Aead, ByteArray, Csprng, Hasher, Kdf, KeyExchange, Mac, Signer},
    },
    core::{array::TryFromSliceError, marker::PhantomData},
};

pub struct Handshake<
    'a,
    A: Aead,
    D: KeyExchange,
    H: Hasher,
    K: Kdf,
    M: Mac,
    S: Signer,
    const W: usize,
> {
    private_key: &'a D::PrivateKey,
    public_key: &'a D::PublicKey,
    _marker: PhantomData<(A, H, K, M, S)>,
}

static CERTIFICATION_CONTEXT: &[u8; 20] = b"autograph/certify/v1";
static INITIATOR_CONTEXT: &[u8; 22] = b"autograph/initiator/v1";
static RESPONDER_CONTEXT: &[u8; 22] = b"autograph/responder/v1";
static AUTHENTICATION_CONTEXT: &[u8; 22] = b"autograph/handshake/v1";
static ROOT_CONTEXT: &[u8; 17] = b"autograph/root/v1";
static SESSION_CONTEXT: &[u8; 20] = b"autograph/session/v1";

impl<'a, A: Aead, D: KeyExchange, H: Hasher, K: Kdf, M: Mac, S: Signer, const W: usize>
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

    pub fn certify(&self, signer: &S) -> Option<Certificate<D, S>> {
        let identity_key = signer.public_key()?;
        let subject = Self::certification_subject(self.public_key);
        let signature = signer.sign(subject.as_ref())?;
        let public_key = D::PublicKey::try_from_slice(self.public_key.as_ref()).ok()?;
        Some(Certificate::new(identity_key, public_key, signature))
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
        K::kdf(ikm.as_ref(), pre_shared_key, ROOT_CONTEXT, secret_key);
        K::kdf(ikm.as_ref(), pre_shared_key, SESSION_CONTEXT, session_key);
        Channel::<A, K, W>::new(
            session_key,
            self.public_key.as_ref(),
            their_public_key.as_ref(),
        )
    }

    pub fn initiator(
        &self,
        their_certificate: &Certificate<D, S>,
        pre_shared_key: Option<&[u8]>,
        secret_key: &mut [u8],
        session_key: &mut [u8],
    ) -> Option<(Channel<A, K, W>, Authenticator<M>)> {
        let subject = Self::certification_subject(&their_certificate.public_key);
        if !S::verify(
            subject.as_ref(),
            &their_certificate.identity_key,
            &their_certificate.signature,
        ) {
            return None;
        }
        let channel = self.establish(
            &their_certificate.public_key,
            pre_shared_key,
            secret_key,
            session_key,
        )?;
        let (sending, receiving, authentication) = Self::authenticate(
            session_key,
            &their_certificate.identity_key,
            self.public_key,
        )?;
        Some((
            channel,
            Authenticator::new(sending, receiving, authentication),
        ))
    }

    pub fn responder(
        &self,
        signer: &S,
        their_public_key: &D::PublicKey,
        pre_shared_key: Option<&[u8]>,
        secret_key: &mut [u8],
        session_key: &mut [u8],
    ) -> Option<(Channel<A, K, W>, Authenticator<M>)> {
        let identity_key = signer.public_key()?;
        let channel = self.establish(their_public_key, pre_shared_key, secret_key, session_key)?;
        let (receiving, sending, authentication) =
            Self::authenticate(session_key, &identity_key, their_public_key)?;
        Some((
            channel,
            Authenticator::new(sending, receiving, authentication),
        ))
    }

    fn authenticate(
        session_key: &[u8],
        responder_identity_key: &S::PublicKey,
        initiator_public_key: &D::PublicKey,
    ) -> Option<(M, M, M)> {
        let initiator = Self::create_mac(
            INITIATOR_CONTEXT,
            session_key,
            responder_identity_key,
            initiator_public_key,
        )?;
        let responder = Self::create_mac(
            RESPONDER_CONTEXT,
            session_key,
            responder_identity_key,
            initiator_public_key,
        )?;
        let authentication = Self::create_mac(
            AUTHENTICATION_CONTEXT,
            session_key,
            responder_identity_key,
            initiator_public_key,
        )?;
        Some((initiator, responder, authentication))
    }

    #[inline(always)]
    fn create_mac(
        context: &[u8],
        session_key: &[u8],
        responder_identity_key: &S::PublicKey,
        initiator_public_key: &D::PublicKey,
    ) -> Option<M> {
        let mut key = H::Output::new();
        K::kdf(session_key, None, context, key.as_mut());
        let mut mac = M::new(key.as_ref())?;
        mac.update(responder_identity_key.as_ref());
        mac.update(initiator_public_key.as_ref());
        Some(mac)
    }
}

pub struct Certificate<D: KeyExchange, S: Signer> {
    identity_key: S::PublicKey,
    public_key: D::PublicKey,
    signature: S::Signature,
}

impl<D: KeyExchange, S: Signer> Certificate<D, S> {
    pub const SIZE: usize = { S::PublicKey::SIZE + D::PublicKey::SIZE + S::Signature::SIZE };

    fn new(identity_key: S::PublicKey, public_key: D::PublicKey, signature: S::Signature) -> Self {
        Self {
            identity_key,
            public_key,
            signature,
        }
    }

    pub fn identity_key(&self) -> &S::PublicKey {
        &self.identity_key
    }

    pub fn public_key(&self) -> &D::PublicKey {
        &self.public_key
    }

    pub fn signature(&self) -> &S::Signature {
        &self.signature
    }

    pub fn serialize<'a>(&self, bytes: &'a mut [u8]) -> Option<&'a [u8]> {
        let (certificate, _) = bytes.split_at_mut_checked(Self::SIZE)?;
        let (identity_key, remaining) = certificate.split_at_mut(S::PublicKey::SIZE);
        let (public_key, signature) = remaining.split_at_mut(D::PublicKey::SIZE);
        identity_key.copy_from_slice(self.identity_key.as_ref());
        public_key.copy_from_slice(self.public_key.as_ref());
        signature.copy_from_slice(self.signature.as_ref());
        Some(certificate)
    }
}

impl<D: KeyExchange, S: Signer> TryFrom<&[u8]> for Certificate<D, S> {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (identity_key, remaining) = bytes
            .split_at_checked(S::PublicKey::SIZE)
            .unwrap_or_default();
        let (public_key, remaining) = remaining
            .split_at_checked(D::PublicKey::SIZE)
            .unwrap_or_default();
        let (signature, _) = remaining
            .split_at_checked(S::Signature::SIZE)
            .unwrap_or_default();
        let identity_key = S::PublicKey::try_from_slice(identity_key)?;
        let public_key = D::PublicKey::try_from_slice(public_key)?;
        let signature = S::Signature::try_from_slice(signature)?;
        Ok(Self::new(identity_key, public_key, signature))
    }
}

pub struct Authenticator<M: Mac> {
    sending: M,
    receiving: M,
    authentication: M,
}

impl<M: Mac> Authenticator<M> {
    fn new(sending: M, receiving: M, authentication: M) -> Self {
        Self {
            sending,
            receiving,
            authentication,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.sending.update(data);
        self.receiving.update(data);
        self.authentication.update(data);
    }

    pub fn authenticate(&self) -> M::Output {
        self.authentication.clone().finalize()
    }

    pub fn code(&self) -> M::Output {
        self.sending.clone().finalize()
    }

    pub fn verify(&self, code: &M::Output) -> bool {
        self.receiving.clone().verify(code)
    }
}
