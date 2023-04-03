import Foundation

internal func createParty(
  isInitiator: Bool,
  identityKeyPair: KeyPair,
  ephemeralKeyPair: KeyPair
) -> Party {
  let calculateSafetyNumber =
    createSafetyNumber(ourIdentityKey: identityKeyPair.publicKey)
  let performHandshake = createHandshake(
    isInitiator: isInitiator,
    identityKeyPair: identityKeyPair,
    ephemeralKeyPair: ephemeralKeyPair
  )
  return Party(
    calculateSafetyNumber: calculateSafetyNumber,
    ephemeralKey: ephemeralKeyPair.publicKey,
    identityKey: identityKeyPair.publicKey,
    performHandshake: performHandshake
  )
}
