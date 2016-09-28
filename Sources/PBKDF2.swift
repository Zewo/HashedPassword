// PBKDF2.swift
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

#if os(Linux)
	import Glibc
#else
	import Darwin.C
#endif

import OpenSSL

fileprivate extension UInt {
	var data: Data {
		var inti = Array<UInt8>(repeating: 0, count: 4)
		inti[0] = UInt8((self >> 24) & 0xFF)
		inti[1] = UInt8((self >> 16) & 0xFF)
		inti[2] = UInt8((self >> 8) & 0xFF)
		inti[3] = UInt8(self & 0xFF)
		return Data(bytes: inti)
	}
}

internal enum PBKDF2Error: Error {
	case invalidInput
	case derivedKeyTooLong
}

internal struct PBKDF2 {
	
	private let dkLen: Int
	private let password: Data
	private let salt: Data
	private let iterations: Int
	private let numBlocks: UInt
	private let hashType: Hash.Function
	
	internal static func calculate(password: Data, salt: Data, iterations: Int = 4096, keyLength: Int? = nil, hashType: Hash.Function = .sha256) throws -> Data {
		return try PBKDF2(password: password, salt: salt, iterations: iterations, keyLength: keyLength, hashType: hashType).calculate()
	}
	
	private init(password: Data, salt: Data, iterations: Int = 4096, keyLength: Int? = nil, hashType: Hash.Function = .sha256) throws {
		guard iterations > 0 && !password.isEmpty && !salt.isEmpty else {
			throw PBKDF2Error.invalidInput
		}
		
		self.dkLen = keyLength ?? hashType.digestLength
		let keyLengthFinal = Double(dkLen)
		let hLen = Double(hashType.digestLength)
		if keyLengthFinal > (pow(2,32) - 1) * hLen {
			throw PBKDF2Error.derivedKeyTooLong
		}
		
		self.password = password
		self.salt = salt
		self.iterations = iterations
		self.numBlocks = UInt(ceil(keyLengthFinal / hLen))
		self.hashType = hashType
	}
	
	private func calculate() -> Data {
		var ret = Data()
		for i in 1 ... numBlocks {
			if let value = calculateBlock(salt, blockNum: i) {
				ret.append(contentsOf: value)
			}
		}
		return Data(ret.prefix(dkLen))
	}
	
	private func calculateBlock(_ salt: Data, blockNum: UInt) -> Data? {
		var u = Hash.hmac(hashType, key: password, message: salt + blockNum.data)
		var ret = u
		if iterations > 1 {
			for _ in 2 ... iterations {
				u = Hash.hmac(hashType, key: password, message: u)
				for x in 0 ..< ret.count {
					ret[x] = ret[x] ^ u[x]
				}
			}
		}
		return ret
	}
	
}
