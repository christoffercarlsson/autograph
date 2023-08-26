import Foundation

internal func createParty(
  isInitiator: Bool,
  sign: @escaping SignFunction,
  identityPublicKey: Bytes
) -> Party {
  Party(
    calculateSafetyNumber: createSafetyNumber(
      ourIdentityKey: identityPublicKey
    ),
    performKeyExchange: createKeyExchange(
      isInitiator: isInitiator,
      sign: sign,
      identityPublicKey: identityPublicKey
    )
  )
}
