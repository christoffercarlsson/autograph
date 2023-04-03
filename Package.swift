// swift-tools-version: 5.8

import PackageDescription

let package = Package(
  name: "Autograph",
  products: [
    .library(
      name: "Clibautograph",
      targets: ["Clibautograph"]
    ),
    .library(
      name: "Autograph",
      targets: ["Autograph"]
    ),
  ],
  dependencies: [],
  targets: [
    .binaryTarget(
      name: "Clibautograph",
      path: "swift/Clibautograph.xcframework"
    ),
    .target(
      name: "Autograph",
      dependencies: ["Clibautograph"],
      path: "swift/Sources/Autograph"
    ),
    .testTarget(
      name: "AutographTests",
      dependencies: ["Autograph"],
      path: "swift/Tests/AutographTests"
    ),
  ]
)
