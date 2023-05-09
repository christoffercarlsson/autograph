# The Autograph Protocol

Revision 3 (Draft 3), 2023-05-09

Christoffer Carlsson (editor)

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. Preliminaries](#2-preliminaries)
  - [2.1. Cryptographic notation](#21-cryptographic-notation)
  - [2.2. Roles](#22-roles)
  - [2.3. Keys](#23-keys)
  - [2.4. Message indexing](#24-message-indexing)
- [3. The Autograph protocol](#3-the-autograph-protocol)
  - [3.1. Handshake](#31-handshake)
  - [3.2. Identity verification](#32-identity-verification)
  - [3.3. Encrypted messages](#33-encrypted-messages)
  - [3.4. Certifying ownership](#34-certifying-ownership)
  - [3.5. Verifying ownership](#35-verifying-ownership)
- [4. Security considerations](#4-security-considerations)
  - [4.1. Key compromise](#41-key-compromise)
  - [4.2. Identity verification](#42-identity-verification)
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

### 2.1 Cryptographic notation

This document will use the following notation:

- The concatenation of byte sequences **X** and **Y** is **X || Y**.
- **ENCRYPT(K, N, M)** represents the ChaCha20-Poly1305 \[[1](#7-references)\]
  encryption of plaintext M with the 256-bit key K. The nonce N is a 32-bit
  big-endian unsigned integer padded on the left with 8 zero-filled bytes. The
  128-bit authentication tag is appended to the ciphertext.
- **DECRYPT(K, N, C)** represents the ChaCha20-Poly1305 decryption of ciphertext
  C with the key K and nonce N.
- **DH(PK1, PK2)** represents 32 bytes of shared secret output from the X25519
  \[[2](#7-references)\] Elliptic Curve Diffie-Hellman (ECDH)
  \[[3](#7-references)\] function involving the key pairs represented by public
  keys PK1 and PK2.
- **SIGN(PK, M)** represents a byte sequence that is an Edwards-curve Digital
  Signature Algorithm (EdDSA) \[[4](#7-references)\] signature on the byte
  sequence M and verifies with the public key PK, and was created using PK's
  corresponding private key. The signing and verification function will be
  Ed25519 \[[5](#7-references)\].
- **KDF(KM, C)** represents 32 bytes of output from the HKDF algorithm
  \[[6](#7-references)\], using SHA-512 \[[7](#7-references)\], with inputs:
  - Input keying material = The byte sequence KM.
  - Salt = A zero-filled byte sequence with the same length as the output of
    SHA-512 (64 bytes).
  - Info = A single byte C representing the context for the derived key
    material.
- **HASH(M, N)** represents 64 bytes of SHA-512 output produced by iteratively
  hashing the byte sequence M N times.

### 2.2 Roles

The Autograph protocol involves two parties. The protocol allows each party to
send encrypted messages to the other party. The protocol also allows each party
to certify and verify the ownership of the other party's cryptographic identity
and the message contents.

The only distinguishing factor between the two parties during a protocol run is
that the party who initiates the handshake (i.e. sends their ephemeral public
key first) as described in [Section 3.1](#31-handshake) is the known as the
**initiator** and the other party is known as the **responder**. Being the
initiator or responder affects the order of calculations that a party performs
during the handshake.

To simplify description this document will use the role **Alice** to refer to
the initiator, and the role **Bob** to refer to the responder.

### 2.3 Keys

Autograph will use the following elliptic curve public keys:

| Name           | Definition            | Form    |
| :------------- | :-------------------- | :------ |
| IK<sub>A</sub> | Alice's identity key  | Ed25519 |
| EK<sub>A</sub> | Alice's ephemeral key | X25519  |
| IK<sub>B</sub> | Bob's identity key    | Ed25519 |
| EK<sub>B</sub> | Bob's ephemeral key   | X25519  |

All public keys have corresponding private keys, but to simplify description
this document will focus on the public keys.

In Autograph, X25519 public keys will use the little-endian encoding of the
u-coordinate as specified in \[[2](#7-references)\]. Ed25519 public keys will
use the little-endian encoding as specified in \[[4](#7-references)\]. The
resulting byte sequences for X25519 and Ed25519 public keys will be 32 bytes
long.

Prior to a protocol run each party has two key pairs:

1. An Ed25519 identity key pair with public key IK used for signing
   (IK<sub>A</sub> for Alice, IK<sub>B</sub> for Bob).
2. An X25519 ephemeral key pair with public key EK (EK<sub>A</sub> for Alice,
   EK<sub>B</sub> for Bob) used for key agreement.

Identity key pairs can be used in multiple protocol runs. Ephemeral key pairs
are only used once for a single protocol run.

During a handshake each party involved will derive a 32-byte secret key SK
(SK<sub>A</sub> for Alice, SK<sub>B</sub> for Bob).

### 2.4 Message indexing

Each encrypted message that a party sends is indexed by a 32-bit big-endian
unsigned integer N. The index is one-based. N is increased by 1 for each new
message. The first message is assigned index 1, the second message is assigned
index 2, the third message 3, and so on:

N<sub>1</sub> = 1, N<sub>2</sub> = 2, N<sub>3</sub> = 3 ... N<sub>i</sub> = i

By having N be a 32-bit unsigned integer there is an implicit maximum number
(2<sup>32</sup> - 1) of messages that each party can send during the same
protocol run.

## 3. The Autograph protocol

### 3.1 Handshake

This section describes how two parties agree on two 32-byte shared secret keys
that will be used to secure their communication during this protocol run. Alice
and Bob agree on the shared secret keys SK<sub>A</sub> and SK<sub>B</sub> by
performing the following steps:

Through some mechanism, each party obtains the other party's identity key IK
(IK<sub>A</sub> for Alice, IK<sub>B</sub> for Bob).

Alice sends her EK<sub>A</sub> public key to Bob.

Upon receiving EK<sub>A</sub> from Alice, Bob creates a signature S<sub>B</sub>
by calculating:

S<sub>B</sub> = SIGN(IK<sub>B</sub>, IK<sub>A</sub> || IK<sub>B</sub> ||
EK<sub>A</sub> || EK<sub>B</sub>)

The S<sub>B</sub> signature certifies that Bob is in control of the
IK<sub>B</sub> private key.

Bob performs the following DH calculation:

KM = DH(EK<sub>B</sub>, EK<sub>A</sub>)

Bob then derives two secret keys, SK<sub>A</sub> and SK<sub>B</sub>, by
calculating:

SK<sub>A</sub> = KDF(KM, 0x00)\
SK<sub>B</sub> = KDF(KM, 0x01)

Bob deletes KM and his EK<sub>B</sub> private key.

Bob then encrypts the S<sub>B</sub> signature using the SK<sub>B</sub> secret
key, producing the ciphertext H<sub>B</sub>:

H<sub>B</sub> = ENCRYPT(SK<sub>B</sub>, 0, S<sub>B</sub>)

Bob sends his EK<sub>B</sub> public key and H<sub>B</sub> to Alice.

Upon receiving EK<sub>B</sub> and H<sub>B</sub> from Bob, Alice repeats the
above DH and KDF calculations to derive the SK<sub>A</sub> and SK<sub>B</sub>
secret keys. She deletes KM and her EK<sub>A</sub> private key.

Alice then attempts to decrypt H<sub>B</sub> using SK<sub>B</sub>:

S<sub>B</sub> = DECRYPT(SK<sub>B</sub>, 0, H<sub>B</sub>)

If the decryption fails, Alice aborts the protocol. If the decryption succeeds,
Alice verifies the signature S<sub>B</sub>. If the verification fails, Alice
aborts the protocol.

If the verification succeeds, Alice creates the signature S<sub>A</sub> by
calculating:

S<sub>A</sub> = SIGN(IK<sub>A</sub>, IK<sub>A</sub> || IK<sub>B</sub> ||
EK<sub>A</sub> || EK<sub>B</sub>)

The S<sub>A</sub> signature certifies that Alice is in control of the
IK<sub>A</sub> private key.

Alice then encrypts the S<sub>A</sub> signature using the SK<sub>A</sub> secret
key, producing the ciphertext H<sub>A</sub>:

H<sub>A</sub> = ENCRYPT(SK<sub>A</sub>, 0, S<sub>A</sub>)

Alice sends H<sub>A</sub> to Bob.

Upon receiving H<sub>A</sub> from Alice, Bob attempts to decrypt it using
SK<sub>A</sub>:

S<sub>A</sub> = DECRYPT(SK<sub>A</sub>, 0, H<sub>A</sub>)

If the decryption fails, Bob aborts the protocol. If the decryption succeeds,
Bob verifies the S<sub>A</sub> signature. If the verification fails, Bob aborts
the protocol.

If the verification succeeds, Alice and Bob have now established two 32-byte
secret keys, SK<sub>A</sub> and SK<sub>B</sub>, that will be used to secure
their communication during this protocol run.

The ability to derive the correct SK<sub>A</sub> and SK<sub>B</sub> secret keys
combined with the successful verification of the S<sub>A</sub> and S<sub>B</sub>
signatures authenticates the handshake and certifies that both Alice and Bob are
in control of their IK and EK private keys.

### 3.2 Identity verification

This section describes how two parties can manually verify each other's identity
keys to prevent man-in-the-middle attacks by calculating a safety number. The
verification can be done either before or after a protocol run. Alice and Bob
verify each other's identity keys by performing the following steps:

Alice computes a 30-digit numeric fingerprint FH<sub>A</sub> for her identity
key IK<sub>A</sub>:

FH<sub>A</sub> = HASH(IK<sub>A</sub>, 5200)

Alice takes the first 30 bytes of FH<sub>A</sub> and splits them into six 5-byte
chunks. She converts each 5-byte chunk into 5 digits by interpreting each chunk
as a big-endian unsigned integer and reducing it modulo 100000 (if the result is
an integer with less than 5 digits it is padded on the left with zeroes).

Alice then concatenates the 6 groups of 5 digits into 30 digits to produce her
fingerprint FP<sub>A</sub>.

Upon obtaining Bob's identity key IK<sub>B</sub>, Alice repeats the above steps
to produce Bob's fingerprint FP<sub>B</sub>.

Alice compares the FP<sub>A</sub> and FP<sub>B</sub> fingerprints
lexicographically to determine her safety number SN<sub>A</sub>.

If FP<sub>A</sub> is lexicographically less than FP<sub>B</sub>:

SN<sub>A</sub> = FP<sub>A</sub> || FP<sub>B</sub>

If FP<sub>A</sub> is lexicographically greater than FP<sub>B</sub>:

SN<sub>A</sub> = FP<sub>B</sub> || FP<sub>A</sub>

Upon obtaining Alice's identity key IK<sub>A</sub>, Bob repeats the above steps
to calculate his safety number SN<sub>B</sub>.

Alice and Bob manually compare each other's safety numbers out-of-band. If they
don't match both parties abort the protocol.

If the safety numbers match Alice and Bob have successfully verified each
other's identity keys.

### 3.3 Encrypted messages

This section describes how two parties sends encrypted messages to each other.
The receiving party is able to decrypt the messages and verify that they
actually came from the sender and that they haven't been tampered with in
transit. Alice and Bob exchange encrypted messages with each other by performing
the following steps:

Alice and Bob performs a handshake as described in [Section 3.1](#31-handshake).
Optionally, they also perform an identity verification as described in
[Section 3.2](#32-identity-verification).

For each message that Alice sends to Bob the following steps are performed:

Alice indexes the message using the 32-bit big-endian unsigned integer N as
described in [Section 2.4](#24-message-indexing).

The plaintext data that Alice wants to send to Bob is represented by the byte
sequence D<sub>NA</sub>.

Alice encrypts the plaintext D<sub>NA</sub> using the secret key SK<sub>A</sub>,
producing the ciphertext E<sub>NA</sub>. She prepends the message index N to the
ciphtertext, producing the message M<sub>NA</sub>:

E<sub>NA</sub> = ENCRYPT(SK<sub>A</sub>, N, D<sub>NA</sub>)\
M<sub>NA</sub> = N || E<sub>NA</sub>

Alice sends M<sub>NA</sub> to Bob.

Upon receiving M<sub>NA</sub> from Alice, Bob attempts to decrypt the ciphertext
E<sub>NA</sub>:

D<sub>NA</sub> = DECRYPT(SK<sub>A</sub>, N, E<sub>NA</sub>)

If the decryption fails Bob aborts the protocol.

If decryption succeeds, Bob has successfully verified that the data
D<sub>NA</sub> was sent by Alice and that it hasn't been tampered with in
transit.

Alice increases the value of the message index N by 1 for each new message that
she sends.

Alice and Bob repeats the above steps for each message that Alice sends to Bob.

By repeating the above steps, Bob can send encrypted messages back to Alice
using the SK<sub>B</sub> secret key.

### 3.4 Certifying ownership

This section describes how one party can certifies the ownership of another
party's cryptographic identity key IK and optionally some data D. Bob certifies
Alice's ownership by performing the following steps:

Alice and Bob performs a handshake as described in [Section 3.1](#31-handshake).
Optionally, they also perform an identity verification as described in
[Section 3.2](#32-identity-verification).

Optionally, Alice sends some data D<sub>NA</sub> in an encrypted message to Bob
as described in [Section 3.3](#33-encrypted-messages).

If the origin and integrity of Alice's data D<sub>NA</sub> was verified
successfully, Bob creates the signature C<sub>NA</sub> that certifies that
certifies Alice's ownership of her identity key IK<sub>A</sub> and data
D<sub>NA</sub>:

C<sub>NA</sub> = SIGN(IK<sub>B</sub>, D<sub>NA</sub> || IK<sub>A</sub>)

If Alice did not send any data D<sub>NA</sub>, Bob creates the signature
C<sub>A</sub> that certifies Alice's ownership of her identity key
IK<sub>A</sub> by calculating:

C<sub>A</sub> = SIGN(IK<sub>B</sub>, IK<sub>A</sub>)

The above steps can be repeated for each message that Alice sends to Bob.

By obtaining the signatures C<sub>NA</sub> or C<sub>A</sub>, and Bob's identity
key IK<sub>B</sub>, other parties can verify Alice's ownership in future
protocol runs without further contact with Bob. The mechanism by which
certifying signatures are obtained by other parties is beyond the scope of this
document, but subject to the security considerations in
[Section 4.3](#43-trusted-party-manipulation).

By repeating the above steps Alice can certify Bob's ownership of his identity
key IK<sub>B</sub> and each message containing data D<sub>NB</sub> by creating
the signatures C<sub>NB</sub> and/or C<sub>B</sub>.

How a party verifies another party's ownership is explained in the next section.

### 3.5 Verifying ownership

This section describes how a party verifies another party's ownership of their
identity key IK and optionally some data D. Bob verifies Alice's ownership by
performing the following steps:

Alice and Bob performs a handshake as described in [Section 3.1](#31-handshake).
Optionally, they also perform an identity verification as described in
[Section 3.2](#32-identity-verification).

Optionally, Alice sends her data D<sub>NA</sub> in an encrypted message to Bob,
as described in [Section 3.3](#33-encrypted-messages).

Through some mechanism, Bob obtains the identity keys IK and corresponding
certifiying signatures C of some number of trusted third parties that in
previous protocol runs have certified Alice's ownership of her identity key
IK<sub>A</sub> and optionally data D<sub>NA</sub> as described in
[Section 3.4](34-certifying-ownership). The specifics of how Bob determines
which identity keys and signatures he obtains for a given protocol run is beyond
the scope of this document, but subject to the security considerations in
[Section 4.3](#43-trusted-party-manipulation).

If the origin and integrity of Alice's data D<sub>NA</sub> was verified
successfully, Bob verifies each of the obtained signatures C<sub>NA</sub> using
their corresponding IK public key, Alice's identity key IK<sub>A</sub> and the
data D<sub>NA</sub>. If any of the verifications fail Bob aborts the protocol.
If all verifications succeed Bob has successfully verified Alice's ownership of
her identity key IK<sub>A</sub> and data D<sub>NA</sub>.

If Alice did not send any data D<sub>NA</sub> to Bob, he verifies each of the
obtained signatures C<sub>A</sub> using their corresponding identity keys IK and
Alice's identity key IK<sub>A</sub>. If any of the verifications fail Bob aborts
the protocol. If all verifications succeed Bob has successfully verified Alice's
ownership of her identity key IK<sub>A</sub>.

Alice can send multiple encrypted messages to Bob and given that he is able to
obtain the correct identity keys IK and certifying signatures C, Bob can repeat
the above steps to verify Alice's ownership of each piece of data
D<sub>NA</sub>.

By repeating the above steps, Bob can send encrypted messages back to Alice and
she can verify Bob's ownership of his identity key IK<sub>B</sub> and optionally
data D<sub>NB</sub>.

## 4. Security considerations

### 4.1 Key compromise

If a party's long-term identity private key IK is compromised, an attacker may
impersonate that party to others.

If a party's ephemeral private key EK is compromised prior to a given protocol
run, an attacker may derive SK and thereby have the ability to tamper with the
contents of the encrypted messages M being sent between the two parties involved
in that protocol run.

### 4.2 Identity verification

If an identity verification as described in
[Section 3.2](#32-identity-verification) is not performed, the parties will have
no cryptographic guarantee as to who they are communicating with, which may
enable man-in-the-middle attacks.

### 4.3 Trusted party manipulation

If a malicious party is able to manipulate the mechanism through which another
party obtains the IK public keys and certifying signatures C from trusted third
parties they could add or remove the public keys and signatures of other parties
(including their own), thus bypassing the ownership verification described in
[Section 3.5](#35-verifying-ownership). Therefore, implementers of the protocol
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

Thanks to Elnaz Abolahrar for discussions around allowing a party's ownership of
their cryptographic identity and data to be certified by a dynamic number of
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
