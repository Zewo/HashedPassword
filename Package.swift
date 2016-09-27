import PackageDescription

let package = Package(
    name: "HashedPassword",
    dependencies: [
		.Package(url: "https://github.com/Zewo/Core.git", majorVersion: 0, minor: 13),
		.Package(url: "https://github.com/Zewo/OpenSSL.git", majorVersion: 0, minor: 13)
    ]
)
