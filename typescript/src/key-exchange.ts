import { createSignature } from './cert'
import {
  autograph_key_exchange,
  autograph_verify_key_exchange,
  autograph_transcript_size
} from './clib'
import { createSecretKey } from './message'

export const createTranscript = () =>
  new Uint8Array(autograph_transcript_size())

export const keyExchange = (
  isInitiator: boolean,
  ourIdentityKeyPair: Uint8Array,
  ourSessionKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSessionKey: Uint8Array
): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] => {
  const transcript = createTranscript()
  const ourSignature = createSignature()
  const sendingKey = createSecretKey()
  const receivingKey = createSecretKey()
  const success = autograph_key_exchange(
    transcript,
    ourSignature,
    sendingKey,
    receivingKey,
    isInitiator,
    ourIdentityKeyPair,
    ourSessionKeyPair,
    theirIdentityKey,
    theirSessionKey
  )
  if (!success) {
    throw new Error('Key exchange failed')
  }
  return [transcript, ourSignature, sendingKey, receivingKey]
}

export const verifyKeyExchange = (
  transcript: Uint8Array,
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSignature: Uint8Array
) => {
  const success = autograph_verify_key_exchange(
    transcript,
    ourIdentityKeyPair,
    theirIdentityKey,
    theirSignature
  )
  if (!success) {
    throw new Error('Key exchange verification failed')
  }
}
