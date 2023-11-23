import { autograph_init, autograph_safety_number } from './clib'
import { createSafetyNumberBytes } from './utils'
import { InitializationError, SafetyNumberCalculationError } from './error'

const calculateSafetyNumber = async (
  a: Uint8Array,
  b: Uint8Array
): Promise<Uint8Array> => {
  if ((await autograph_init()) < 0) {
    throw new InitializationError()
  }
  const safetyNumber = createSafetyNumberBytes()
  const success = autograph_safety_number(safetyNumber, a, b) === 0
  if (!success) {
    throw new SafetyNumberCalculationError()
  }
  return safetyNumber
}

export default calculateSafetyNumber
