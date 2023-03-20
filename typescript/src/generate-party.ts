import { createParty } from './create-party'
import { generateKeyPair } from './generate-key-pair'

const generateParty = async (isInitiator: boolean) => {
  const keyPair = await generateKeyPair()
  return createParty(isInitiator, keyPair)
}

export const generateAlice = () => generateParty(true)

export const generateBob = () => generateParty(false)
