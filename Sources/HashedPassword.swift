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
import CryptoSwift

public enum HashedPasswordError: Error {
	case invalidString
}

public enum HashMethod: Equatable {
	case hash(variant: HMAC.Variant)
	case hmac(variant: HMAC.Variant)
	case pbkdf2(variant: HMAC.Variant, iterations: Int)
	
	internal init?(string: String) {
		let comps = string.components(separatedBy: "_")
		guard let methodStr = comps.first else { return nil }
		switch methodStr {
		case "hash":
			guard comps.count == 2, let hashType = HMAC.Variant(string: comps[1]) else { return nil }
			self = .hash(variant: hashType)
		case "hmac":
			guard comps.count == 2, let hashType = HMAC.Variant(string: comps[1]) else { return nil }
			self = .hmac(variant: hashType)
		case "pbkdf2":
			guard comps.count == 3, let hashType = HMAC.Variant(string: comps[1]), let iterations = Int(comps[2]) else { return nil }
			self = .pbkdf2(variant: hashType, iterations: iterations)
		default:
			return nil
		}
	}
	
	internal var string: String {
		switch self {
		case .hash(let variant):
			return "hash_" + variant.string
		case .hmac(let variant):
			return "hmac_" + variant.string
		case .pbkdf2(let variant, let iterations):
			return "pbkdf2_" + variant.string + "_" + String(iterations)
		}
	}
	
	internal func calculate(password: String, salt: String) throws -> String {
		guard let saltData = salt.data(using: .utf8)?.bytes,
			  let passwordData = password.data(using: .utf8)?.bytes else { throw HashedPasswordError.invalidString }
		
		let data: [UInt8]
		switch self {
		case .hash(let variant):
			data = variant.calculateHash(saltData+passwordData)
		case .hmac(let variant):
			data = try HMAC(key: saltData, variant: variant).authenticate(passwordData)
		case .pbkdf2(let variant, let iterations):
			data = try PKCS5.PBKDF2(password: passwordData, salt: saltData, iterations: iterations, variant: variant).calculate()
		}
		
		return data.reduce("", { $0 + String(format: "%02x", $1) })
	}
	
	public static func ==(lhs: HashMethod, rhs: HashMethod) -> Bool {
		return true
	}
}

public struct HashedPassword: Equatable, CustomStringConvertible {

	public let hash: String
	public let method: HashMethod
	public let salt: String
	
	public init(hash: String, method: HashMethod, salt: String) {
		self.hash = hash
		self.method = method
		self.salt = salt
	}
	
	public init(string: String) throws {
		let passwordComps = string.components(separatedBy: "$")
		guard passwordComps.count == 3, let method = HashMethod(string: passwordComps[1]) else { throw HashedPasswordError.invalidString }
		self.init(hash: passwordComps[0], method: method, salt: passwordComps[2])
	}
	
	public init(password: String, method: HashMethod = .pbkdf2(variant: .sha256, iterations: 4096), saltLen: Int = 30) throws {
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
