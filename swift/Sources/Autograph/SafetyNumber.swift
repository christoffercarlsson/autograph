import Clibautograph
import Foundation

internal func createSafetyNumber(ourIdentityKey: Bytes)
  -> SafetyNumberFunction
{
  let safetyNumberFunction: SafetyNumberFunction =
    { [ourIdentityKey] theirIdentityKey in
      var safetyNumber = createSafetyNumberBytes()
      let success = autograph_safety_number(
        &safetyNumber,
        ourIdentityKey,
        theirIdentityKey
      ) == 0
      return SafetyNumberResult(success: success, safetyNumber: safetyNumber)
    }
  return safetyNumberFunction
}
