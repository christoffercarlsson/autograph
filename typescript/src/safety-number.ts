import { autograph_safety_number } from './clib'
import { createSafetyNumberBytes } from './utils'
import { SafetyNumberCalculationError } from './error'

const calculateSafetyNumber = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const safetyNumber = createSafetyNumberBytes()
  const success = autograph_safety_number(safetyNumber, a, b)
  if (!success) {
    throw new SafetyNumberCalculationError()
  }
  return safetyNumber
}

export default calculateSafetyNumber
