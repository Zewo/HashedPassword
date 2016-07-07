// HashedPassword.swift
//
// The MIT License (MIT)
//
// Copyright (c) 2016 Zewo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDINbG BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

@_exported import POSIX
@_exported import OpenSSL
@_exported import String

private extension HashType {
	init?(string: String) {
		switch string {
		case "sha1":	self = .SHA1
		case "sha224":	self = .SHA224
		case "sha256":	self = .SHA256
		case "sha384":	self = .SHA384
		case "sha512":	self = .SHA512
		default:			return nil
		}
	}
	
	var string: String {
		switch self {
		case .SHA1:		return "sha1"
		case .SHA224:	return "sha224"
		case .SHA256:	return "sha256"
		case .SHA384:	return "sha384"
		case .SHA512:	return "sha512"
		}
	}
	
	func hash(salt: String, message: String) -> String {
		return Hash.hmac(self, key: salt.data, message: message.data).hexadecimalString().lowercased()
	}
}

public struct HashedPassword: Equatable, CustomStringConvertible {
	
	public enum Error: ErrorProtocol {
		case invalidString
	}
	
	public let hash: String
	public let hashType: HashType
	public let salt: String
	
	public init(hash: String, hashType: HashType, salt: String) {
		self.hash = hash
		self.hashType = hashType
		self.salt = salt
	}
	
	public init(string: String) throws {
		let passwordComps = string.split(separator: "$")
		guard passwordComps.count == 3, let hashType = HashType(string: passwordComps[1]) else { throw Error.invalidString }
		self.init(hash: passwordComps[0], hashType: hashType, salt: passwordComps[2])
	}
	
	private static func rand(max: Int) -> Int {
		#if os(Linux)
			return Int(random() % (max + 1))
		#else
			return Int(arc4random_uniform(UInt32(max)))
		#endif
	}
	
	public init(password: String, hashType: HashType = .SHA1) {
		let pool = Array(CharacterSet.letters.characters)
		var salt = ""
		for _ in 0 ..< 22 {
			let i = HashedPassword.rand(max: pool.count - 1)
			salt += String(pool[i])
		}
		self.hashType = hashType
		self.salt = salt
		self.hash = hashType.hash(salt: salt, message: password)
	}

	public var description: String {
		return "\(hash)$\(hashType.string)$\(salt)"
	}
	
}

public func ==(lhs: HashedPassword, rhs: HashedPassword) -> Bool {
	return lhs.hash == rhs.hash && lhs.hashType == rhs.hashType && lhs.salt == rhs.salt
}

public func ==(lhs: HashedPassword, rhs: String) -> Bool {
	return lhs.hashType.hash(salt: lhs.salt, message: rhs) == lhs.hash.lowercased()
}

public func ==(lhs: String, rhs: HashedPassword) -> Bool { return rhs == lhs }
