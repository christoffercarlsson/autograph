import { concat } from 'stedy/bytes'
import { CertifyFunction } from '../types'
import signMessage from './sign-message'

const createCertify =
  (
    ourPrivateKey: BufferSource,
    theirPublicKey: BufferSource
  ): CertifyFunction =>
  (data?: BufferSource) =>
    signMessage(ourPrivateKey, concat([data, theirPublicKey]))

export default createCertify
