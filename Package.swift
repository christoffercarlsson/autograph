// swift-tools-version: 5.8

import PackageDescription

let package = Package(
    name: "Autograph",
    products: [
        .library(
            name: "Autograph",
            targets: ["Autograph"]
        ),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "Clibautograph",
            path: "apple/Clibautograph.xcframework"
        ),
        .target(
            name: "Autograph",
            dependencies: ["Clibautograph"],
            path: "apple/Sources/Autograph"
        ),
        .testTarget(
            name: "AutographTests",
            dependencies: ["Autograph"],
            path: "apple/Tests/AutographTests"
        ),
    ]
)
