import Clibautograph
import Foundation

func createBytes(_ size: Int) -> [UInt8] {
    [UInt8](repeating: 0, count: size)
}

public func ready() throws {
    if !autograph_ready() {
        throw AutographError.initialization
    }
}
