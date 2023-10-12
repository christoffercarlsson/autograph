import { autograph_safety_number } from './clib'
import { SafetyNumberFunction } from '../types'
import { createSafetyNumberBytes } from './utils'

const createSafetyNumber =
  (ourIdentityKey: Uint8Array): SafetyNumberFunction =>
  (theirIdentityKey: Uint8Array) => {
    const safetyNumber = createSafetyNumberBytes()
    const success = autograph_safety_number(
      safetyNumber,
      ourIdentityKey,
      theirIdentityKey
    )
    return { success, safetyNumber }
  }

export default createSafetyNumber
