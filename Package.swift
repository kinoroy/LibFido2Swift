// swift-tools-version: 5.9.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibFido2Swift",
    platforms: [.macOS(.v10_15)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "LibFido2Swift",
            targets: ["LibFido2Swift"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "LibFido2Swift",
            dependencies: ["LibCrypto", "libfido2", "LibCbor"],
            path: "LibFido2Swift"
        ),
        .binaryTarget(name: "LibCbor", path: "./Frameworks/LibCbor.xcframework"),
        .binaryTarget(name: "LibCrypto", path: "./Frameworks/LibCrypto.xcframework"),
        .binaryTarget(name: "libfido2", path: "./Frameworks/libfido2.xcframework"),
    ]
)
