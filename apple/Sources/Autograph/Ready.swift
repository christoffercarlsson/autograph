import Clibautograph
import Foundation

public func ready() throws {
    if !autograph_ready() {
        throw AutographError.initialization
    }
}
