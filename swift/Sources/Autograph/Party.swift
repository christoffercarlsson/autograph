import Foundation

internal func createParty(
  isInitiator: Bool,
  sign: @escaping SignFunction,
  identityPublicKey: Bytes
) -> Party {
  let calculateSafetyNumber =
    createSafetyNumber(ourIdentityKey: identityPublicKey)
  let performHandshake = createHandshake(
    isInitiator: isInitiator,
    sign: sign,
    identityPublicKey: identityPublicKey
  )
  return Party(
    calculateSafetyNumber: calculateSafetyNumber,
    performHandshake: performHandshake
  )
}
