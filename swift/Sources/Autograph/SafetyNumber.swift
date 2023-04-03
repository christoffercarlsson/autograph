import Clibautograph
import Foundation

internal func createSafetyNumber(ourIdentityKey: Bytes)
  -> SafetyNumberFunction
{
  let safetyNumberFunction: SafetyNumberFunction = { theirIdentityKey in
    var safetyNumber = createSafetyNumberBytes()
    let result = autograph_safety_number(
      getMutablePointer(&safetyNumber),
      getPointer(ourIdentityKey),
      getPointer(theirIdentityKey)
    )
    if result != 0 {
      throw AutographError.safetyNumberFailed
    }
    return safetyNumber
  }
  return safetyNumberFunction
}
