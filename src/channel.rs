use {
    crate::primitives::{Aead, ByteArray, Kdf},
    core::marker::PhantomData,
};

pub struct Channel<A: Aead, K: Kdf, const W: usize> {
    sending_key: A::SecretKey,
    receiving_key: A::SecretKey,
    receiving_window: ReceivingWindow<W>,
    _marker: PhantomData<(A, K)>,
}

impl<A: Aead, K: Kdf, const W: usize> Channel<A, K, W> {
    pub fn new(
        session_key: &[u8],
        sending_context: &[u8],
        receiving_context: &[u8],
    ) -> Option<Self> {
        if sending_context == receiving_context {
            return None;
        }
        let mut sending_key = A::SecretKey::new();
        let mut receiving_key = A::SecretKey::new();
        K::kdf(session_key, None, sending_context, sending_key.as_mut());
        K::kdf(session_key, None, receiving_context, receiving_key.as_mut());
        Some(Self {
            sending_key,
            receiving_key,
            receiving_window: ReceivingWindow::<W>::new(),
            _marker: PhantomData,
        })
    }

    pub fn send(
        &self,
        nonce: &mut A::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
    ) -> Option<(u64, A::Tag)> {
        let index = A::increment_nonce(nonce)?;
        let tag = A::encrypt(&self.sending_key, nonce, aad, message);
        Some((index, tag))
    }

    pub fn receive(
        &mut self,
        nonce: &A::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
        tag: &A::Tag,
    ) -> Option<u64> {
        if A::decrypt(&self.receiving_key, nonce, aad, message, tag) {
            let index = A::read_index(nonce);
            if self.receiving_window.mark(index) {
                Some(index)
            } else {
                None
            }
        } else {
            None
        }
    }
}

struct ReceivingWindow<const W: usize> {
    top: u64,
    bitmap: [u64; W],
}

impl<const W: usize> ReceivingWindow<W> {
    const BITS: u64 = (W as u64).saturating_mul(64);

    fn new() -> Self {
        assert!(W > 0, "Window size W must be non-zero");
        Self {
            top: 0,
            bitmap: [0u64; W],
        }
    }

    fn mark(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if self.top == 0 {
            self.top = counter;
            self.bitmap = [0u64; W];
            self.set_bit(counter);
            return true;
        }
        if counter.saturating_add(Self::BITS) <= self.top {
            return false;
        }
        if counter <= self.top {
            if self.is_set(counter) {
                return false;
            }
            self.set_bit(counter);
            return true;
        }
        let advance = counter - self.top;
        if advance >= Self::BITS {
            self.bitmap = [0u64; W];
        } else {
            for c in (self.top + 1)..counter {
                self.clear_bit(c);
            }
        }
        self.top = counter;
        self.set_bit(counter);
        true
    }

    fn slot(counter: u64) -> (usize, u64) {
        let bit = (counter % Self::BITS) as usize;
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        (word, mask)
    }

    fn clear_bit(&mut self, counter: u64) {
        let (word, mask) = Self::slot(counter);
        self.bitmap[word] &= !mask;
    }

    fn set_bit(&mut self, counter: u64) {
        let (word, mask) = Self::slot(counter);
        self.bitmap[word] |= mask;
    }

    fn is_set(&self, counter: u64) -> bool {
        let (word, mask) = Self::slot(counter);
        self.bitmap[word] & mask != 0
    }
}
