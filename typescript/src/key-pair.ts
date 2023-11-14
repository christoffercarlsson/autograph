import { KeyPair } from '../types'
import {
  autograph_key_pair_ephemeral,
  autograph_key_pair_identity
} from './clib'
import { KeyPairGenerationError } from './error'
import { createPrivateKeyBytes, createPublicKeyBytes } from './utils'

const createKeyPair = () => ({
  privateKey: createPrivateKeyBytes(),
  publicKey: createPublicKeyBytes()
})

export const generateEphemeralKeyPair = (): KeyPair => {
  const keyPair = createKeyPair()
  const success = autograph_key_pair_ephemeral(
    keyPair.privateKey,
    keyPair.publicKey
  )
  if (!success) {
    throw new KeyPairGenerationError()
  }
  return keyPair
}

export const generateIdentityKeyPair = (): KeyPair => {
  const keyPair = createKeyPair()
  const success = autograph_key_pair_identity(
    keyPair.privateKey,
    keyPair.publicKey
  )
  if (!success) {
    throw new KeyPairGenerationError()
  }
  return keyPair
}
