// Utilities.swift
//
// The MIT License (MIT)
//
// Copyright (c) 2017 Zewo
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

#if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
	import Darwin
#elseif os(Linux)
	import Glibc
#endif
import Foundation
import CryptoSwift

internal class Random {
	internal static func number(max: Int = Int(UInt32.max)) -> Int {
		#if os(OSX) || os(iOS) || os(tvOS) || os(watchOS)
			return Int(arc4random_uniform(UInt32(max)))
		#elseif os(Linux)
			return Int(random() % (max + 1))
		#endif
	}
}

internal extension HMAC.Variant {
	internal init?(string: String) {
		switch string {
		case "md5":		self = .md5
		case "sha1":	self = .sha1
			
		case "sha256":	self = .sha256
		case "sha384":	self = .sha384
		case "sha512":	self = .sha512
		default:		return nil
		}
	}
	
	internal var string: String {
		switch (self) {
		case .sha1:		return "sha1"
		case .sha256:	return "sha256"
		case .sha384:	return "sha384"
		case .sha512:	return "sha512"
		case .md5:		return "md5"
		}
	}
	
	internal func calculateHash(_ bytes: Array<UInt8>) -> Array<UInt8> {
		switch (self) {
		case .sha1:
			return Digest.sha1(bytes)
		case .sha256:
			return Digest.sha256(bytes)
		case .sha384:
			return Digest.sha384(bytes)
		case .sha512:
			return Digest.sha512(bytes)
		case .md5:
			return Digest.md5(bytes)
		}
	}
}
