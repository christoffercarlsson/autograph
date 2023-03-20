import { hash as digest } from 'stedy'

const hash = (message: BufferSource, iterations: number) =>
  digest(message, iterations)

export default hash
