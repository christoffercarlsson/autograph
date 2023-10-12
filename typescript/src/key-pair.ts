import { KeyPairResult } from '../types'
import {
  autograph_key_pair_ephemeral,
  autograph_key_pair_identity
} from './clib'
import { createPrivateKeyBytes, createPublicKeyBytes } from './utils'

const createKeyPair = () => ({
  privateKey: createPrivateKeyBytes(),
  publicKey: createPublicKeyBytes()
})

export const generateEphemeralKeyPair = (): KeyPairResult => {
  const keyPair = createKeyPair()
  const success = autograph_key_pair_ephemeral(
    keyPair.privateKey,
    keyPair.publicKey
  )
  return { success, keyPair }
}

export const generateIdentityKeyPair = (): KeyPairResult => {
  const keyPair = createKeyPair()
  const success = autograph_key_pair_identity(
    keyPair.privateKey,
    keyPair.publicKey
  )
  return { success, keyPair }
}
