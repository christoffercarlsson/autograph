import { importKey } from 'stedy'

export const importPrivateKey = (key: BufferSource) =>
  importKey(key, false, false)

export const importPrivateSignKey = (key: BufferSource) =>
  importKey(key, true, false)

export const importPublicKey = (key: BufferSource) =>
  importKey(key, false, true)

export const importPublicSignKey = (key: BufferSource) =>
  importKey(key, true, true)
