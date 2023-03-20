import { Chunk, createFrom } from 'stedy/bytes'
import { CalculateSafetyNumberFunction } from '../types'
import { SAFETY_NUMBER_DIVISOR, SAFETY_NUMBER_ITERATIONS } from './constants'
import hash from './crypto/hash'

const encodeChunk = (chunk: Chunk) => {
  const [a, b, c, d, e] = chunk
  const number =
    (a * 2 ** 32 + b * 2 ** 24 + c * 2 ** 16 + d * 2 ** 8 + e) %
    SAFETY_NUMBER_DIVISOR
  const result = number.toString()
  return `${'0'.repeat(5 - result.length)}${result}`
}

const calculate = async (identityKey: BufferSource) => {
  const digest = await hash(identityKey, SAFETY_NUMBER_ITERATIONS)
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

const createCalculateSafetyNumber =
  (ourIdentityKey: BufferSource): CalculateSafetyNumberFunction =>
  (theirIdentityKey: BufferSource) =>
    calculateSafetyNumber(ourIdentityKey, theirIdentityKey)

export default createCalculateSafetyNumber
