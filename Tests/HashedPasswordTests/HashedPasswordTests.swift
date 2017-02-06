import XCTest
@testable import HashedPassword

class HashedPasswordTests: XCTestCase {
	func testHashedPassword() throws {
		let hashed1 = try HashedPassword(string: "1293b6cf05902a0333ed1db991f296d36641491fb2afb83fca968e8a4a80b7cb$pbkdf2_sha256_4096$ALCKgWoguBGWikAqMErOIFmSmYlUVL")
		XCTAssert(hashed1 == "test1")
		
		let hashed2 = try HashedPassword(string: "d500a1fb233ca92cfc960e0411e186a4f2e8d267$pbkdf2_sha1_1024$eXpncMALpDTGVasmeneBkA")
		XCTAssert(hashed2 == "test2")
		
		let hashed3 = try HashedPassword(string: "00b902718d496f07b86e4fc32df31083f2c82690$hash_sha1$WffQVliOqZkUORlHDlHPux")
		XCTAssert(hashed3 == "test3")
	}
}

extension HashedPasswordTests {
    static var allTests: [(String, (HashedPasswordTests) -> () throws -> Void)] {
		return [
			("testHashedPassword", testHashedPassword),
        ]
    }
}
