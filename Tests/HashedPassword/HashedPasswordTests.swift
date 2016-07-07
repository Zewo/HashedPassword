import XCTest
@testable import HashedPassword

class HashedPasswordTests: XCTestCase {
    func testReality() {
        XCTAssert(2 + 2 == 4, "Something is severely wrong here.")
    }
}

extension HashedPasswordTests {
    static var allTests: [(String, (HashedPasswordTests) -> () throws -> Void)] {
        return [
           ("testReality", testReality),
        ]
    }
}
