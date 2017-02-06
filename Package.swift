import PackageDescription

let package = Package(
    name: "HashedPassword",
    dependencies: [
		.Package(url: "https://github.com/krzyzanowskim/CryptoSwift", majorVersion: 0, minor: 6)
    ]
)
