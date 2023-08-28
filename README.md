# The Autograph Protocol

Revision 3 (Draft 4), 2023-08-22

Christoffer Carlsson (editor)

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. Preliminaries](#2-preliminaries)
  - [2.1. External functions](#21-external-functions)
  - [2.2. Roles](#22-roles)
  - [2.3. Keys](#23-keys)
  - [2.4. Message indexing](#24-message-indexing)
  - [2.5. State variables](#25-state-variables)
- [3. The Autograph protocol](#3-the-autograph-protocol)
  - [3.1. Initialization](#31-initialization)
  - [3.2. Key exchange](#32-key-exchange)
  - [3.3. Out-of-band verification](#33-out-of-band-verification)
  - [3.4. Encrypted messaging](#34-encrypted-messaging)
  - [3.5. Certifying ownership](#35-certifying-ownership)
    - [3.5.1. Certifying data](#351-certifying-data)
    - [3.5.2. Certifying identity](#352-certifying-identity)
    - [3.5.3. Obtaining signatures](#353-obtaining-signatures)
  - [3.6. Verifying ownership](#36-verifying-ownership)
    - [3.6.1. Verifying data](#361-verifying-data)
    - [3.6.2. Verifying identity](#362-verifying-identity)
- [4. Security considerations](#4-security-considerations)
  - [4.1. Key compromise](#41-key-compromise)
  - [4.2. Out-of-band verification](#42-out-of-band-verification)
  - [4.3. Trusted party manipulation](#43-trusted-party-manipulation)
- [5. IPR](#5-ipr)
- [6. Acknowledgements](#6-acknowledgements)
- [7. References](#7-references)

## 1. Introduction

This document describes the Autograph protocol. The protocol enables the
following scenarios:

1. **Encrypted messaging**: Two parties can exchange encrypted messages that
   each can be verified to have originated from the sender and have not been
   tampered with in transit.
2. **Ownership verification**: Additionally, both parties can verify the
   ownership of each other's cryptographic identity and the message contents by
   relying on cryptographic signatures from trusted third parties.

Autograph provides cryptographic deniability and forward secrecy.

## 2. Preliminaries

### 2.1 External functions

Autograph requires defining the following functions:

- **CONCAT(X, Y)** returns the concatenation of byte sequences **X** and **Y**.
- **ENCRYPT(K, N, M)** returns the ciphertext of the ChaCha20-Poly1305
  \[[1](#7-references)\] encryption of plaintext **M** with the 256-bit key
  **K**. The nonce **N** is a 64-bit big-endian unsigned integer padded on the
  left with 4 zero-filled bytes. The 128-bit authentication tag is appended to
  the ciphertext.
- **DECRYPT(K, N, C)** returns plaintext of the ChaCha20-Poly1305 decryption of
  ciphertext **C** with the key **K** and nonce **N**.
- **DH(K1, K2)** returns 32 bytes of shared secret output from the X25519
  \[[2](#7-references)\] Elliptic Curve Diffie-Hellman (ECDH)
  \[[3](#7-references)\] function involving the private key **K1** and the
  public key **K2**.
- **SIGN(K, M)** returns a 64-byte sequence that is an Edwards-curve Digital
  Signature Algorithm (EdDSA) \[[4](#7-references)\] signature on the byte
  sequence **M** that was created using the private key **K**, and verifies
  using K's corresponding public key. The signing and verification function will
  be Ed25519 \[[5](#7-references)\].
- **VERIFY(K, S, M)** returns a boolean value that is the result of verifying
  the signature byte sequence **S** using the public key **K** and the byte
  sequence **M**.
- **KDF(KM, C)** returns 32 bytes of output from the HKDF algorithm
  \[[6](#7-references)\], using SHA-512 \[[7](#7-references)\], with inputs:
  - Input keying material = The byte sequence **KM**.
  - Salt = A zero-filled byte sequence with the same length as the output of
    SHA-512 (64 bytes).
  - Info = An 8-bit unsigned integer **C** representing the context for the
    derived key material.
- **HASH(M, N)** returns 64 bytes of SHA-512 output produced by iteratively
  hashing the byte sequence **M** **N** times.

### 2.2 Roles

The Autograph protocol involves two parties. The protocol allows each party to
send encrypted messages to the other party. The protocol also allows each party
to certify and verify the ownership of the other party's cryptographic identity
and the message contents.

The only distinguishing factor between the two parties during a protocol run is
that the party who initiates the key exchange (i.e. sends their ephemeral public
key first) as described in [Section 3.2](#32-key-exchange) is the known as the
**initiator** and the other party is known as the **responder**. Being the
initiator or responder affects the order of calculations that a party performs
during the key exchange.

To simplify description this document will use the role **Alice** to refer to
the initiator, and the role **Bob** to refer to the responder.

### 2.3 Keys

Autograph will use the following elliptic curve key pairs:

| Name           | Definition                 | Form    |
| :------------- | :------------------------- | :------ |
| IK<sub>A</sub> | Alice's identity key pair  | Ed25519 |
| IK<sub>B</sub> | Bob's identity key pair    | Ed25519 |
| EK<sub>A</sub> | Alice's ephemeral key pair | X25519  |
| EK<sub>B</sub> | Bob's ephemeral key pair   | X25519  |

In Autograph, X25519 public keys will use the little-endian encoding of the
u-coordinate as specified in \[[2](#7-references)\]. Ed25519 public keys will
use the little-endian encoding as specified in \[[4](#7-references)\]. The
resulting byte sequences for X25519 and Ed25519 public keys will be 32 bytes
long.

Autograph will use the following symmetric secret keys:

| Name           | Definition         |
| :------------- | :----------------- |
| SK<sub>A</sub> | Alice's secret key |
| SK<sub>B</sub> | Bob's secret key   |

Secret keys will be 32 bytes long.

### 2.4 Message indexing

Each message is indexed by a 64-bit big-endian unsigned integer N (N<sub>A</sub>
for Alice, N<sub>B</sub> for Bob). The index is one-based. N is increased by 1
for each new message being sent. The first message is assigned index 1, the
second message is assigned index 2, the third message 3, and so on:

N<sub>1</sub> = 1, N<sub>2</sub> = 2, N<sub>3</sub> = 3 ... N<sub>i</sub> = i

### 2.5 State variables

Each party tracks the following state variables:

| Name | Definition                                        |
| :--- | :------------------------------------------------ |
| IK   | The other party's identity public key             |
| EK   | The other party's ephemeral public key            |
| SKs  | Secret key for sending                            |
| SKr  | Secret key for receiving                          |
| Ns   | Message index for sending                         |
| T    | Transcript of identity- and ephemeral public keys |

In the Python code that follows, the state variables are accessed as members of
a **state** object.

## 3. The Autograph protocol

### 3.1 Initialization

To initialize a protocol run, each party calls **Init()**:

```python
def Init(state):
  state.IK = None
  state.EK = None
  state.SKs = None
  state.SKr = None
  state.Ns = 0
  state.T = None
```

### 3.2 Key exchange

This section describes how two parties agree on two shared secret keys that will
be used to secure their communication during this protocol run. Alice and Bob
agree on the shared secret keys SK<sub>A</sub> and SK<sub>B</sub> by performing
the following steps:

Through some mechanism, Alice obtains Bob's IK<sub>B</sub> public key and
through some, potentially different, mechanism Bob obtains Alice's
IK<sub>A</sub> public key.

Alice sends her EK<sub>A</sub> public key to Bob.

Upon receiving the EK<sub>A</sub> public key from Alice, Bob derives the secret
keys SK<sub>A</sub> and SK<sub>B</sub> and produces the ciphertext H<sub>B</sub>
by calling _KeyExchangeBob()_:

```python
def KeyExchangeBob(
  state,
  bob_identity_private_key,
  bob_identity_public_key,
  bob_ephemeral_private_key,
  bob_ephemeral_public_key,
  alice_identity_public_key,
  alice_ephemeral_public_key
):
  state.IK = alice_identity_public_key
  state.EK = alice_ephemeral_public_key
  ikm = DH(bob_ephemeral_private_key, state.EK)
  state.SKs = KDF(ikm, 1)
  state.SKr = KDF(ikm, 0)
  state.T = CONCAT(state.IK, bob_identity_public_key)
  state.T = CONCAT(state.T, state.EK)
  state.T = CONCAT(state.T, bob_ephemeral_public_key)
  return ENCRYPT(state.SKs, 0, SIGN(bob_identity_private_key, state.T))
```

Bob deletes his EK<sub>B</sub> private key. He then sends his EK<sub>B</sub>
public key and H<sub>B</sub> to Alice.

Upon receiving the EK<sub>B</sub> public key and H<sub>B</sub> from Bob, Alice
derives the secret keys SK<sub>A</sub> and SK<sub>B</sub> and produces the
ciphertext H<sub>A</sub> by calling _KeyExchangeAlice()_:

```python
def KeyExchangeAlice(
  state,
  alice_identity_private_key,
  alice_identity_public_key,
  alice_ephemeral_private_key,
  alice_ephemeral_public_key,
  bob_identity_public_key,
  bob_ephemeral_public_key
):
  state.IK = bob_identity_public_key
  state.EK = bob_ephemeral_public_key
  ikm = DH(alice_ephemeral_private_key, state.EK)
  state.SKs = KDF(ikm, 0)
  state.SKr = KDF(ikm, 1)
  state.T = CONCAT(alice_identity_public_key, state.IK)
  state.T = CONCAT(state.T, alice_ephemeral_public_key)
  state.T = CONCAT(state.T, state.EK)
  return ENCRYPT(state.SKs, 0, SIGN(alice_identity_private_key, state.T))
```

Alice deletes her EK<sub>A</sub> private key. She then sends H<sub>A</sub> to
Bob and calls _VerifyKeyExchange()_ with H<sub>B</sub>:

```python
def VerifyKeyExchange(state, h):
  return VERIFY(state.IK, DECRYPT(state.SKr, 0, h), state.T)
```

If the verification fails, Alice aborts the protocol.

Upon receiving the ciphertext from Alice, Bob calls _VerifyKeyExchange()_ with
H<sub>A</sub>. If the verification fails, Bob aborts the protocol.

If both verifications succeeds, Alice and Bob have now established two 32-byte
secret keys, SK<sub>A</sub> and SK<sub>B</sub>, that will be used to secure
their communication during this protocol run.

The ability to derive the correct SK<sub>A</sub> and SK<sub>B</sub> secret keys
combined with the successful verification of H<sub>A</sub> and H<sub>B</sub>
authenticates the key exchange and certifies that both Alice and Bob are in
control of their IK and EK private keys.

### 3.3 Out-of-band verification

This section describes how two parties can manually verify each other's identity
keys to prevent man-in-the-middle attacks by calculating a safety number. Alice
and Bob verify each other's identity keys by performing the following steps:

Alice and Bob performs a key exchange as described in
[Section 3.2](#32-key-exchange).

Alice computes the safety number SN<sub>A</sub> by calling _SafetyNumber()_ with
her IK<sub>A</sub> public key:

```python
def SafetyNumber(state, identity_public_key):
  f1 = CalculateFingerprint(identity_public_key)
  f2 = CalculateFingerprint(state.IK)
  return CONCAT(f1, f2) if f1 < f2 else CONCAT(f2, f1)

def CalculateFingerprint(identity_public_key):
  digest = HASH(identity_public_key, 5200)
  chunks = [digest[i:i+5] for i in range(0, 30, 5)]
  encoded_chunks = [EncodeChunk(chunk) for chunk in chunks]
  return CONCAT(encoded_chunks)

def EncodeChunk(chunk):
  a, b, c, d, e = chunk
  number = (a * 2 ** 32 + b * 2 ** 24 + c * 2 ** 16 + d * 2 ** 8 + e) % 100000
  result = str(number)
  return bytes('0' * (5 - len(result)) + result)
```

Bob computes the safety number SN<sub>B</sub> by calling _SafetyNumber()_ with
his IK<sub>B</sub> public key.

Alice and Bob manually compare each other's safety numbers SN<sub>A</sub> and
SN<sub>B</sub> out-of-band. If they don't match both parties abort the protocol.

If the safety numbers match Alice and Bob have successfully verified each
other's identity keys.

### 3.4 Encrypted messaging

This section describes how two parties sends encrypted messages to each other.
The receiving party is able to decrypt the messages and verify that they
actually came from the sender and that they haven't been tampered with in
transit. Alice and Bob exchange encrypted messages with each other by performing
the following steps:

Alice and Bob performs a key exchange as described in
[Section 3.2](#32-key-exchange). Optionally, they also perform an out-of-band
verification as described in [Section 3.3](#33-out-of-band-verification).

For each message that Alice sends to Bob the following steps are performed:

Alice encrypts some plaintext D<sub>N<sub>A</sub></sub> with the secret key
SK<sub>A</sub> by calling _EncryptMessage()_ with D<sub>N<sub>A</sub></sub>,
producing the message M<sub>N<sub>A</sub></sub>:

```python
def EncryptMessage(state, d):
  state.Ns += 1
  return CONCAT(state.Ns, ENCRYPT(state.SKs, state.Ns, d))
```

Alice sends M<sub>N<sub>A</sub></sub> to Bob.

Upon receiving the message from Alice, Bob attempts to decrypt it by calling
_DecryptMessage()_ with M<sub>N<sub>A</sub></sub>:

```python
def DecryptMessage(state, m):
  return DECRYPT(state.SKr, m[:8], m[8:])
```

If the decryption fails, Bob aborts the protocol.

If decryption succeeds, Bob has successfully verified that the plaintext
D<sub>N<sub>A</sub></sub> was sent by Alice and that it hasn't been tampered
with in transit.

By repeating the above steps, Bob can send encrypted messages back to Alice
using the SK<sub>B</sub> secret key.

### 3.5 Certifying ownership

This section describes how one party can certifies the ownership of another
party's IK identity private key and optionally some data D.

Alice and Bob performs a key exchange as described in
[Section 3.2](#32-key-exchange). Optionally, they also perform an out-of-band
verification as described in [Section 3.3](#33-out-of-band-verification).

#### 3.5.1 Certifying data

Upon receiving some message M<sub>N<sub>A</sub></sub> from Alice as described in
[Section 3.4](#34-encrypted-messaging), Bob can choose to certify Alice's
ownership of the plaintext D<sub>N<sub>A</sub></sub>. He produces the plaintext
by calling _DecryptMessage()_ with M<sub>N<sub>A</sub></sub>. Bob then produces
the signature C<sub>N<sub>A</sub></sub> by calling _SignData()_ with his
IK<sub>B</sub> private key and the plaintext D<sub>N<sub>A</sub></sub>:

```python
def SignData(state, identity_private_key, d):
  subject = CONCAT(d, state.IK)
  return SIGN(identity_private_key, subject)
```

If the decryption fails, Bob aborts the protocol.

If the decryption succeeds, Bob has successfully certified Alice's ownership of
her IK<sub>A</sub> private key and the plaintext D<sub>N<sub>A</sub></sub>.

By repeating the above steps, Alice can certify Bob's ownership of some
plaintext D<sub>N<sub>B</sub></sub>.

#### 3.5.2 Certifying identity

Bob can choose to certify Alice's ownership of her IK<sub>A</sub> private key.
He produces the signature C<sub>A</sub> by calling _SignIdentity()_ with his
IK<sub>B</sub> private key:

```python
def SignIdentity(state, identity_private_key):
  return SIGN(identity_private_key, state.IK)
```

By repeating the above steps, Alice can certify Bob's ownership of his
IK<sub>B</sub> private key.

#### 3.5.3 Obtaining signatures

By obtaining the signatures C<sub>A</sub> and/or C<sub>N<sub>A</sub></sub>, and
Bob's IK<sub>B</sub> public key, other parties can verify Alice's ownership in
future protocol runs. Conversely, other parties can verify Bob's ownership in
future protocol runs by obtaining the signatures C<sub>B</sub> and/or
C<sub>N<sub>B</sub></sub>, and Alice's IK<sub>A</sub> public key.

The mechanism(s) by which certifying signatures are obtained by other parties
and the specifics of how a party determines which identity keys and signatures
they obtains for a given protocol run is beyond the scope of this document, but
subject to the security considerations in
[Section 4.3](#43-trusted-party-manipulation).

### 3.6 Verifying ownership

This section describes how a party verifies another party's ownership of their
private identity key IK and optionally some data D.

Alice and Bob performs a key exchange as described in
[Section 3.2](#32-key-exchange). Optionally, they also perform an out-of-band
verification as described in [Section 3.3](#33-out-of-band-verification).

#### 3.6.1 Verifying data

Bob can choose to verify Alice's ownership of some plaintext
D<sub>N<sub>A</sub></sub> by performing the following steps:

Through some mechanism, Bob obtains the identity public keys IK and
corresponding certifiying signatures C<sub>N<sub>A</sub></sub> of some number of
trusted third parties that in previous protocol runs have certified Alice's
ownership of some data D<sub>N<sub>A</sub></sub> as described in
[Section 3.5.1](#351-certifying-data) and
[Section 3.5.3](#353-obtaining-signatures).

Upon receiving the message M<sub>N<sub>A</sub></sub> from Alice as described in
[Section 3.4](#34-encrypted-messaging), Bob can choose to verify Alice's
ownership of the plaintext D<sub>N<sub>A</sub></sub>. He produces the plaintext
by calling _DecryptMessage()_ with M<sub>N<sub>A</sub></sub>. Bob then produces
the verification result by calling _VerifyData()_ with the plaintext
D<sub>N<sub>A</sub></sub> and the set of obtained IK public key and signatures
C<sub>N<sub>A</sub></sub>:

```python
def VerifyData(state, d, certs):
  subject = CONCAT(d, state.IK)
  for cert in certs:
    if not VERIFY(cert.public_key, cert.signature, subject):
      return False
  return True
```

If the decryption fails, Bob aborts the protocol.

If the decryption succeeds and if all verifications succeed Bob has successfully
verified Alice's ownership of the plaintext D<sub>N<sub>A</sub></sub>.

By repeating the above steps, Alice can verify Bob's ownership of some plaintext
D<sub>N<sub>B</sub></sub>.

#### 3.6.2 Verifying identity

Bob can choose to verify Alice's ownership of her IK<sub>A</sub> private key by
performing the following steps:

Through some mechanism, Bob obtains the identity public keys IK and
corresponding certifiying signatures C<sub>A</sub> of some number of trusted
third parties that in previous protocol runs have certified Alice's ownership of
her IK<sub>A</sub> private key as described in
[Section 3.5.2](#352-certifying-identity) and
[Section 3.5.3](#353-obtaining-signatures).

Bob produces the verification result by calling _VerifyIdentity()_ with the set
of obtained IK public keys and signatures C<sub>A</sub>:

```python
def VerifyIdentity(state, certs):
  for cert in certs:
    if not VERIFY(cert.public_key, cert.signature, state.IK):
      return False
  return True
```

If all verifications succeed Bob has successfully verified Alice's ownership of
her IK<sub>A</sub> private key.

By repeating the above steps, Alice can verify Bob's ownership of his
IK<sub>B</sub> private key.

## 4. Security considerations

### 4.1 Key compromise

If a party's long-term identity private key IK is compromised, an attacker may
impersonate that party to others.

If a party's ephemeral private key EK is compromised prior to a given protocol
run, an attacker may derive SK and thereby have the ability to tamper with the
contents of the encrypted messages M being sent between the two parties involved
in that protocol run.

### 4.2 Out-of-band verification

If an out-of-band verification as described in
[Section 3.3](#33-out-of-band-verification) is not performed, the parties will
have no cryptographic guarantee as to who they are communicating with, which may
enable man-in-the-middle attacks.

### 4.3 Trusted party manipulation

If a malicious party is able to manipulate the mechanism through which another
party obtains the IK public keys and certifying signatures C from trusted third
parties they could add or remove the public keys and signatures of other parties
(including their own), thus bypassing the ownership verification described in
[Section 3.6](#36-verifying-ownership). Therefore, implementers of the protocol
should take the appropriate steps to prevent unauthorized access to the
mechanism through which parties obtains public keys and signatures of trusted
third parties. How to implement these preventive measures is beyond the scope of
this document.

## 5. IPR

This document is hereby placed in the public domain.

## 6. Acknowledgements

The original Autograph concept was developed by Christoffer Carlsson and Max
Molin.

The Autograph protocol was designed by Christoffer Carlsson.

Thanks to Elnaz Abolahrar for discussions around ownership verification and
trusted third parties.

## 7. References

[1] Y. Nir and A. Langley, “ChaCha20 and Poly1305 for IETF Protocols”; Internet
Research Task Force; RFC 8439; June 2018. <https://www.ietf.org/rfc/rfc8439.txt>

[2] A. Langley, M. Hamburg, and S. Turner, “Elliptic Curves for Security”;
Internet Engineering Task Force; RFC 7748; January 2016.
<https://www.ietf.org/rfc/rfc7748.txt>

[3] D. McGrew, K. Igoe, and M. Salter, “Fundamental Elliptic Curve Cryptography
Algorithms”; Internet Engineering Task Force; RFC 6090; February 2011.
<https://www.ietf.org/rfc/rfc6090.txt>

[4] S. Josefsson and I. Liusvaara, “Edwards-Curve Digital Signature Algorithm
(EdDSA)”; Internet Engineering Task Force; RFC 8032; January 2017.
<https://www.ietf.org/rfc/rfc8032.txt>

[5] D. Bernstein, N. Duif, T. Lange, P. Schwabe, and B. Yang, "High-speed
high-security signatures"; September 2011.
<https://ed25519.cr.yp.to/ed25519-20110926.pdf>

[6] H. Krawczyk and P. Eronen, “HMAC-based Extract-and-Expand Key Derivation
Function (HKDF)”; Internet Engineering Task Force; RFC 5869; May 2010.
<https://www.ietf.org/rfc/rfc5869.txt>

[7] National Institute of Standards and Technology, "Secure Hash Standard
(SHS)"; Federal Information Processing Standards Publication 180-4;
August, 2015. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
