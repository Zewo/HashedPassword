#if os(Linux)

import XCTest
@testable import HashedPasswordTestSuite

XCTMain([
  testCase(HashedPasswordTests.allTests),
])
#endif
