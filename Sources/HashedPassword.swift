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

import Foundation
import Axis
import OpenSSL

internal extension Hash.Function {
	internal init?(string: String) {
		switch string {
		case "md5":		self = .md5
		case "sha1":	self = .sha1
		case "sha224":	self = .sha224
		case "sha256":	self = .sha256
		case "sha384":	self = .sha384
		case "sha512":	self = .sha512
		default:			return nil
		}
	}
	
	internal var string: String {
		switch self {
		case .md5:		return "md5"
		case .sha1:		return "sha1"
		case .sha224:	return "sha224"
		case .sha256:	return "sha256"
		case .sha384:	return "sha384"
		case .sha512:	return "sha512"
		}
	}
}

public enum HashedPasswordError: Error {
	case invalidString
}

public struct HashedPassword: Equatable, CustomStringConvertible {
	
	public enum Method: Equatable {
		case hash(hashType: Hash.Function)
		case hmac(hashType: Hash.Function)
		case pbkdf2(hashType: Hash.Function, iterations: Int)
		
		internal init?(string: String) {
			let comps = string.split(separator: "_")
			guard let methodStr = comps.first else { return nil }
			switch methodStr {
			case "hash":
				guard comps.count == 2, let hashType = Hash.Function(string: comps[1]) else { return nil }
				self = .hash(hashType: hashType)
			case "hmac":
				guard comps.count == 2, let hashType = Hash.Function(string: comps[1]) else { return nil }
				self = .hmac(hashType: hashType)
			case "pbkdf2":
				guard comps.count == 3, let hashType = Hash.Function(string: comps[1]), let iterations = Int(comps[2]) else { return nil }
				self = .pbkdf2(hashType: hashType, iterations: iterations)
			default:
				return nil
			}
		}
		
		internal var string: String {
			switch self {
			case .hash(let hashType):
				return "hash_" + hashType.string
			case .hmac(let hashType):
				return "hmac_" + hashType.string
			case .pbkdf2(let hashType, let iterations):
				return "pbkdf2_" + hashType.string + "_" + String(iterations)
			}
		}
		
		internal func calculate(password: String, salt: String) throws -> String {
			let data: Buffer
			switch self {
			case .hash(let hashType):
				data = Hash.hash(hashType, message: (salt + password).buffer)
			case .hmac(let hashType):
				data = Hash.hmac(hashType, key: salt.buffer, message: password.buffer)
			case .pbkdf2(let hashType, let iterations):
				data = try PBKDF2.calculate(password: password.buffer, salt: salt.buffer, iterations: iterations, hashType: hashType)
			}
			return data.hexadecimalString().lowercased()
		}
		
		public static func ==(lhs: Method, rhs: Method) -> Bool {
			return true
		}
	}
	
	public let hash: String
	public let method: Method
	public let salt: String
	
	public init(hash: String, method: Method, salt: String) {
		self.hash = hash
		self.method = method
		self.salt = salt
	}
	
	public init(string: String) throws {
		let passwordComps = string.split(separator: "$")
		guard passwordComps.count == 3, let method = Method(string: passwordComps[1]) else { throw HashedPasswordError.invalidString }
		self.init(hash: passwordComps[0], method: method, salt: passwordComps[2])
	}
	
	public init(password: String, method: Method = .pbkdf2(hashType: .sha256, iterations: 4096), saltLen: Int = 30) throws {
		let pool = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
		var salt = ""
		for _ in 0 ..< saltLen {
			let i = Random.number(max: pool.count - 1)
			salt += pool[i]
		}
		self.method = method
		self.salt = salt
		self.hash = try method.calculate(password: password, salt: salt)
	}

	public var description: String {
		return "\(hash)$\(method.string)$\(salt)"
	}
	
	public static func ==(lhs: HashedPassword, rhs: HashedPassword) -> Bool {
		return lhs.hash == rhs.hash && lhs.method == rhs.method && lhs.salt == rhs.salt
	}
	
}

public func ==(lhs: HashedPassword, rhs: String) -> Bool {
	return (try? lhs.method.calculate(password: rhs, salt: lhs.salt)) == lhs.hash.lowercased()
}

public func ==(lhs: String, rhs: HashedPassword) -> Bool { return rhs == lhs }
