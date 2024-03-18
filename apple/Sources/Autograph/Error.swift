import Foundation

public enum AutographError: Swift.Error {
    case authentication
    case certification
    case decryption
    case encryption
    case initialization
    case keyExchange
    case keyPair
    case session
}
