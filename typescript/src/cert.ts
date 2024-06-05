import { autograph_certify, autograph_verify } from './clib'
import { createSignature } from './support'

export const certify = (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  data?: Uint8Array
) => {
  const signature = createSignature()
  const success = data
    ? autograph_certify(
        signature,
        ourIdentityKeyPair,
        theirIdentityKey,
        data,
        data.length
      )
    : autograph_certify(
        signature,
        ourIdentityKeyPair,
        theirIdentityKey,
        new Uint8Array(),
        0
      )
  if (!success) {
    throw new Error('Certification failed')
  }
  return signature
}

export const verify = (
  ownerIdentityKey: Uint8Array,
  certifierIdentityKey: Uint8Array,
  signature: Uint8Array,
  data?: Uint8Array
) => {
  const verified = data
    ? autograph_verify(
        ownerIdentityKey,
        certifierIdentityKey,
        signature,
        data,
        data.length
      )
    : autograph_verify(
        ownerIdentityKey,
        certifierIdentityKey,
        signature,
        new Uint8Array(),
        0
      )
  return verified
}
