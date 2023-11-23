export class AutographError extends Error {
  constructor(message: string) {
    super(`Autograph error: ${message}`)
  }
}

export class ChannelAlreadyEstablishedError extends AutographError {
  constructor() {
    super('Channel already established')
  }
}

export class ChannelAlreadyInitializedError extends AutographError {
  constructor() {
    super('Channel already initialized')
  }
}

export class ChannelUnestablishedError extends AutographError {
  constructor() {
    super('Channel unestablished')
  }
}

export class ChannelUninitializedError extends AutographError {
  constructor() {
    super('Channel uninitialized')
  }
}

export class DecryptionError extends AutographError {
  constructor() {
    super('Decryption failed')
  }
}

export class EncryptionError extends AutographError {
  constructor() {
    super('Encryption failed')
  }
}

export class InitializationError extends AutographError {
  constructor() {
    super('Initialization failed')
  }
}

export class KeyExchangeError extends AutographError {
  constructor() {
    super('Key exchange failed')
  }
}

export class KeyExchangeVerificationError extends AutographError {
  constructor() {
    super('Key exchange verification failed')
  }
}

export class KeyPairGenerationError extends AutographError {
  constructor() {
    super('Key pair generation failed')
  }
}

export class SafetyNumberCalculationError extends AutographError {
  constructor() {
    super('Safety number calculation failed')
  }
}

export class SigningError extends AutographError {
  constructor() {
    super('Signing failed')
  }
}
