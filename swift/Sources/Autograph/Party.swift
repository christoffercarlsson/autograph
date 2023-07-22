import Foundation

internal func createParty(
  isInitiator: Bool,
  identityKeyPair: KeyPair
) -> Party {
  let calculateSafetyNumber =
    createSafetyNumber(ourIdentityKey: identityKeyPair.publicKey)
  let performHandshake = createHandshake(
    isInitiator: isInitiator,
    identityKeyPair: identityKeyPair
  )
  return Party(
    calculateSafetyNumber: calculateSafetyNumber,
    performHandshake: performHandshake
  )
}
