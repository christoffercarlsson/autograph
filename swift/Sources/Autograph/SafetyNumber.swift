import Clibautograph
import Foundation

public func calculateSafetyNumber(a: [UInt8], b: [UInt8]) throws -> [UInt8] {
  if autograph_init() < 0 {
    throw AutographError.initialization
  }
  var safetyNumber = createSafetyNumberBytes()
  let success =
    autograph_safety_number(
      &safetyNumber,
      a,
      b
    ) == 0
  if !success {
    throw AutographError.safetyNumberCalculation
  }
  return safetyNumber
}
