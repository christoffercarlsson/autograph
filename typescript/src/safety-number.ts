import { hash } from 'stedy'
import { Chunk, alloc, createFrom } from 'stedy/bytes'
import { SafetyNumberFunction } from '../types'

const encodeChunk = (chunk: Chunk) => {
  const [a, b, c, d, e] = chunk
  const number =
    (a * 2 ** 32 + b * 2 ** 24 + c * 2 ** 16 + d * 2 ** 8 + e) % 100000
  const result = number.toString()
  return `${'0'.repeat(5 - result.length)}${result}`
}

const calculate = async (identityKey: BufferSource) => {
  const digest = await hash(identityKey, 5200)
  return digest
    .subarray(0, 30)
    .split(5)
    .map((chunk) => encodeChunk(chunk))
    .join('')
}

const calculateSafetyNumber = async (
  ourIdentityKey: BufferSource,
  theirIdentityKey: BufferSource
) => {
  const fingerprints = await Promise.all([
    calculate(ourIdentityKey),
    calculate(theirIdentityKey)
  ])
  return createFrom(fingerprints.sort().join(''))
}

const createSafetyNumber =
  (ourIdentityKey: BufferSource): SafetyNumberFunction =>
  async (theirIdentityKey: BufferSource) => {
    try {
      const safetyNumber = await calculateSafetyNumber(
        ourIdentityKey,
        theirIdentityKey
      )
      return { success: true, safetyNumber }
    } catch (error) {
      return { success: false, safetyNumber: alloc(60) }
    }
  }

export default createSafetyNumber
