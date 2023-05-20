import Clibautograph
import Foundation

internal func createSafetyNumber(ourIdentityKey: Bytes)
  -> SafetyNumberFunction
{
  let safetyNumberFunction: SafetyNumberFunction = { [ourIdentityKey] theirIdentityKey in
    var safetyNumber = createSafetyNumberBytes()
    let result = autograph_safety_number(
      &safetyNumber,
      ourIdentityKey,
      theirIdentityKey
    )
    if result != 0 {
      throw AutographError.safetyNumberFailed
    }
    return safetyNumber
  }
  return safetyNumberFunction
}
