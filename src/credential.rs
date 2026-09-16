use {
    crate::primitives::{Csprng, Hasher, Signer},
    core::marker::PhantomData,
};

pub struct Credential<H: Hasher, S: Signer> {
    _marker: PhantomData<(H, S)>,
}

static AUTHENTICATION_CONTEXT: &[u8; 23] = b"autograph/credential/v1";
static CLAIM_CONTEXT: &[u8; 18] = b"autograph/claim/v1";
static ENDORSEMENT_CONTEXT: &[u8; 20] = b"autograph/endorse/v1";
static PRESENTATION_CONTEXT: &[u8; 20] = b"autograph/present/v1";

impl<H: Hasher, S: Signer> Credential<H, S> {
    pub fn authenticate(signer: &S, their_public_key: &S::PublicKey) -> Option<H> {
        let public_key = signer.public_key()?;
        let mut hasher = H::new();
        hasher.update(AUTHENTICATION_CONTEXT);
        if &public_key > their_public_key {
            hasher.update(public_key.as_ref());
            hasher.update(their_public_key.as_ref());
        } else {
            hasher.update(their_public_key.as_ref());
            hasher.update(public_key.as_ref());
        }
        Some(hasher)
    }

    pub fn claim(signer: &S, our_data: &[u8]) -> Option<S::Signature> {
        let subject = Self::claim_subject(our_data);
        signer.sign(subject.as_ref())
    }

    fn claim_subject(data: &[u8]) -> H::Output {
        let mut hasher = H::new();
        hasher.update(CLAIM_CONTEXT);
        hasher.update(data);
        hasher.finalize()
    }

    pub fn endorse(
        signer: &S,
        our_data: Option<&[u8]>,
        their_public_key: &S::PublicKey,
        their_data: &[u8],
        their_signature: &S::Signature,
    ) -> Option<S::Signature> {
        let claim = Self::claim_subject(their_data);
        if !S::verify(claim.as_ref(), their_public_key, their_signature) {
            return None;
        }
        let endorsement =
            Self::endorsement_subject(their_data, our_data.unwrap_or_default(), their_public_key);
        signer.sign(endorsement.as_ref())
    }

    fn endorsement_subject(
        claim: &[u8],
        endorsement: &[u8],
        identity_key: &S::PublicKey,
    ) -> H::Output {
        let mut hasher = H::new();
        hasher.update(ENDORSEMENT_CONTEXT);
        hasher.update(claim);
        hasher.update(endorsement);
        hasher.update(identity_key.as_ref());
        hasher.finalize()
    }

    pub fn generate_challenge(csprng: &mut impl Csprng, challenge: &mut [u8]) {
        csprng.fill(challenge);
    }

    pub fn present(signer: &S, our_data: &[u8], challenge: &[u8]) -> Option<S::Signature> {
        let subject = Self::presentation_subject(our_data, challenge);
        signer.sign(subject.as_ref())
    }

    fn presentation_subject(claim: &[u8], challenge: &[u8]) -> H::Output {
        let mut hasher = H::new();
        hasher.update(PRESENTATION_CONTEXT);
        hasher.update(claim);
        hasher.update(challenge);
        hasher.finalize()
    }

    pub fn verify(
        our_challenge: &[u8],
        their_public_key: &S::PublicKey,
        their_data: &[u8],
        their_signature: &S::Signature,
        endorser_public_key: &S::PublicKey,
        endorsement_data: Option<&[u8]>,
        endorser_signature: &S::Signature,
    ) -> bool {
        let endorsement = Self::endorsement_subject(
            their_data,
            endorsement_data.unwrap_or_default(),
            their_public_key,
        );
        if !S::verify(
            endorsement.as_ref(),
            endorser_public_key,
            endorser_signature,
        ) {
            return false;
        }
        let presentation = Self::presentation_subject(their_data, our_challenge);
        S::verify(presentation.as_ref(), their_public_key, their_signature)
    }
}
