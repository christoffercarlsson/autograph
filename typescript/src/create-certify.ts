import { concat } from 'stedy/bytes'
import { CertifyFunction } from '../types'
import sign from './crypto/sign'

const createCertify =
  (
    ourPrivateKey: BufferSource,
    theirPublicKey: BufferSource
  ): CertifyFunction =>
  (data?: BufferSource) =>
    sign(ourPrivateKey, concat([data, theirPublicKey]))

export default createCertify
