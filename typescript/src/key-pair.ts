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

export const generateEphemeralKeyPair = async (): Promise<KeyPairResult> => {
  const keyPair = createKeyPair()
  const success = await autograph_key_pair_ephemeral(
    keyPair.privateKey,
    keyPair.publicKey
  )
  return { success, keyPair }
}

export const generateIdentityKeyPair = async (): Promise<KeyPairResult> => {
  const keyPair = createKeyPair()
  const success = await autograph_key_pair_identity(
    keyPair.privateKey,
    keyPair.publicKey
  )
  return { success, keyPair }
}
