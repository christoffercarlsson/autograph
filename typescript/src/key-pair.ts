import { KeyPair } from '../../types'
import {
  autograph_init,
  autograph_key_pair_ephemeral,
  autograph_key_pair_identity
} from './clib'
import { InitializationError, KeyPairGenerationError } from './error'
import { createPrivateKeyBytes, createPublicKeyBytes } from './utils'

const createKeyPair = () => ({
  privateKey: createPrivateKeyBytes(),
  publicKey: createPublicKeyBytes()
})

export const generateEphemeralKeyPair = async (): Promise<KeyPair> => {
  if ((await autograph_init()) < 0) {
    throw new InitializationError()
  }
  const keyPair = createKeyPair()
  const success =
    autograph_key_pair_ephemeral(keyPair.privateKey, keyPair.publicKey) === 0
  if (!success) {
    throw new KeyPairGenerationError()
  }
  return keyPair
}

export const generateIdentityKeyPair = async (): Promise<KeyPair> => {
  if ((await autograph_init()) < 0) {
    throw new InitializationError()
  }
  const keyPair = createKeyPair()
  const success =
    autograph_key_pair_identity(keyPair.privateKey, keyPair.publicKey) === 0
  if (!success) {
    throw new KeyPairGenerationError()
  }
  return keyPair
}
