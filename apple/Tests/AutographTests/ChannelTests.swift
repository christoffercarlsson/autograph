import XCTest

@testable import Autograph

final class ChannelTests: XCTestCase {
    let aliceHandshake: Autograph.Bytes = [
        19, 133, 19, 97, 135, 34, 43, 49, 100, 198, 150, 205, 26, 151, 20, 127,
        115,
        193, 120, 209, 25, 46, 221, 194, 223, 118, 62, 0, 135, 6, 112, 250, 198,
        247, 231, 85, 152, 245, 201, 47, 180, 83, 200, 165, 154, 43, 133, 97,
        27,
        25, 35, 233, 170, 220, 170, 38, 185, 233, 61, 160, 12, 117, 73, 8,
    ]

    let bobHandshake: Autograph.Bytes = [
        89, 193, 59, 76, 215, 36, 171, 145, 63, 32, 134, 60, 225, 112, 136, 191,
        176, 64, 42, 18, 210, 2, 33, 212, 243, 245, 230, 147, 182, 20, 81, 101,
        170,
        221, 69, 164, 224, 166, 188, 170, 197, 114, 55, 218, 48, 218, 29, 56,
        98,
        91, 236, 12, 10, 64, 82, 140, 15, 76, 243, 188, 24, 236, 62, 5,
    ]

    let aliceMessage: Autograph.Bytes = [
        51, 243, 8, 165, 206, 25, 129, 63, 124, 51, 176, 40, 21, 4, 178, 3, 128,
        195, 26, 68, 65,
        200, 192, 212, 63, 10, 201, 247, 177, 3, 137, 113,
    ]

    let bobMessage: Autograph.Bytes = [
        253, 199, 105, 203, 139, 136, 132, 228, 198, 157, 65, 140, 116, 90, 212,
        112, 55, 190, 186,
        221, 205, 80, 46, 24, 161, 117, 201, 113, 133, 213, 29, 105,
    ]

    let aliceSignatureBobData: Autograph.Bytes = [
        198, 235, 143, 145, 121, 29, 143, 128, 167, 118, 33, 71, 38, 209, 169,
        2,
        134, 90, 203, 72, 171, 252, 236, 237, 55, 41, 227, 248, 198, 165, 58,
        185,
        31, 70, 147, 96, 181, 33, 188, 7, 146, 43, 24, 197, 158, 216, 215, 49,
        126,
        186, 88, 238, 233, 86, 167, 207, 20, 150, 227, 38, 160, 68, 82, 8,
    ]

    let aliceSignatureBobIdentity: Autograph.Bytes = [
        170, 64, 159, 119, 20, 17, 130, 46, 124, 70, 154, 47, 90, 7, 116, 204,
        255,
        198, 56, 60, 24, 112, 214, 188, 212, 64, 210, 117, 228, 145, 111, 250,
        84,
        20, 216, 222, 21, 82, 213, 225, 31, 28, 152, 211, 16, 82, 131, 7, 248,
        186,
        255, 184, 35, 205, 183, 167, 138, 179, 217, 135, 163, 124, 13, 5,
    ]

    let bobSignatureAliceData: Autograph.Bytes = [
        17, 229, 247, 220, 138, 161, 5, 224, 147, 178, 230, 168, 132, 164, 94,
        3,
        119, 118, 16, 163, 222, 85, 3, 160, 88, 222, 210, 140, 222, 158, 254,
        231,
        182, 232, 78, 211, 150, 146, 127, 164, 238, 221, 119, 12, 230, 54, 49,
        103,
        177, 72, 126, 225, 214, 41, 80, 214, 247, 95, 23, 145, 227, 87, 172, 4,
    ]

    let bobSignatureAliceIdentity: Autograph.Bytes = [
        186, 27, 195, 159, 150, 127, 96, 11, 25, 224, 30, 145, 56, 194, 138,
        164,
        70, 54, 243, 213, 229, 203, 179, 218, 207, 213, 168, 160, 56, 32, 164,
        245,
        49, 102, 200, 36, 172, 152, 113, 5, 82, 196, 154, 90, 20, 27, 180, 61,
        189,
        171, 20, 194, 165, 165, 65, 178, 190, 16, 44, 82, 157, 68, 102, 13,
    ]

    let charlieIdentityKey: Autograph.Bytes = [
        129, 128, 10, 70, 174, 223, 175, 90, 43, 37, 148, 125, 188, 163, 110,
        136,
        15, 246, 192, 76, 167, 8, 26, 149, 219, 223, 83, 47, 193, 159, 6, 3,
    ]

    let charlieSignatureAliceData: Autograph.Bytes = [
        231, 126, 138, 39, 145, 83, 130, 243, 2, 56, 53, 185, 199, 242, 217,
        239,
        118, 208, 172, 6, 201, 132, 94, 179, 57, 59, 160, 23, 150, 221, 67, 122,
        176, 56, 160, 63, 7, 161, 169, 101, 240, 97, 108, 137, 142, 99, 197, 44,
        179, 142, 37, 4, 135, 162, 118, 160, 119, 245, 234, 39, 26, 75, 71, 6,
    ]

    let charlieSignatureAliceIdentity: Autograph.Bytes = [
        146, 120, 170, 85, 78, 187, 162, 243, 234, 149, 138, 201, 18, 132, 187,
        129,
        45, 53, 116, 227, 178, 209, 200, 224, 149, 91, 166, 120, 203, 73, 138,
        189,
        63, 231, 213, 177, 163, 114, 66, 151, 61, 253, 109, 250, 226, 140, 249,
        3,
        188, 44, 127, 108, 196, 131, 204, 216, 54, 239, 157, 49, 107, 202, 123,
        9,
    ]

    let charlieSignatureBobData: Autograph.Bytes = [
        135, 249, 64, 214, 240, 146, 173, 141, 97, 18, 16, 47, 83, 125, 13, 166,
        169, 96, 99, 21, 215, 217, 236, 173, 120, 50, 143, 251, 228, 76, 195, 8,
        248, 133, 170, 103, 122, 169, 190, 57, 51, 14, 171, 199, 229, 55, 55,
        195,
        53, 202, 139, 118, 93, 68, 131, 96, 175, 50, 31, 243, 170, 34, 102, 1,
    ]

    let charlieSignatureBobIdentity: Autograph.Bytes = [
        198, 41, 56, 189, 24, 9, 75, 102, 228, 51, 193, 102, 25, 51, 92, 1, 192,
        219, 16, 17, 22, 28, 22, 16, 198, 67, 248, 16, 98, 164, 99, 243, 254,
        45,
        69, 156, 50, 115, 205, 43, 155, 242, 78, 64, 205, 218, 80, 171, 34, 128,
        255, 51, 237, 60, 37, 224, 232, 149, 153, 213, 204, 93, 26, 7,
    ]

    let data: Autograph.Bytes = [
        72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100,
    ]

    let safetyNumber: Autograph.Bytes = [
        0, 0, 126, 217, 0, 0, 218, 180, 0, 1, 102, 162, 0, 0, 41, 97, 0, 0, 40,
        245,
        0, 1, 15, 218, 0, 0, 12, 28, 0, 0, 98, 95, 0, 0, 96, 224, 0, 0, 16, 147,
        0,
        1, 74, 101, 0, 1, 33, 26, 0, 0, 234, 68, 0, 0, 190, 212, 0, 1, 96, 162,
        0,
        0, 48, 226,
    ]

    let aliceIdentityKeyPair: Autograph.Bytes = [
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2,
        56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88,
        124,
        93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184,
        114, 80, 152, 243,
        24, 225, 91, 220, 141, 150,
    ]

    let bobIdentityKeyPair: Autograph.Bytes = [
        52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17,
        150,
        95, 221, 247, 33,
        201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190, 177, 67,
        45,
        125, 158, 190,
        181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200, 62, 29,
        37, 150, 228, 137,
        114, 143, 77, 115, 135, 143, 103,
    ]

    var a: Autograph.Channel!
    var b: Autograph.Channel!
    var aliceEphemeralKeyPair: Autograph.Bytes!
    var bobEphemeralKeyPair: Autograph.Bytes!
    var handshakeAlice: Autograph.Bytes!
    var handshakeBob: Autograph.Bytes!

    override func setUpWithError() throws {
        aliceEphemeralKeyPair = [
            201, 142, 54, 248, 151, 150, 224, 79, 30, 126, 207, 157, 118, 85, 9,
            212, 148, 156, 73,
            176, 107, 107, 47, 111, 95, 98, 33, 192, 80, 223, 48, 221, 35, 16,
            23,
            37, 205, 131, 166,
            97, 13, 81, 136, 246, 193, 253, 139, 193, 230, 155, 222, 221, 37,
            114,
            190, 87, 104, 44,
            210, 144, 127, 176, 198, 45,
        ]

        bobEphemeralKeyPair = [
            74, 233, 106, 152, 76, 212, 181, 144, 132, 237, 223, 58, 122, 173,
            99, 100, 152, 219, 214,
            210, 213, 72, 171, 73, 167, 92, 199, 196, 176, 66, 213, 208, 88,
            115,
            171, 4, 34, 181, 120,
            21, 10, 39, 204, 215, 158, 210, 177, 243, 28, 138, 52, 91, 236, 55,
            30,
            117, 10, 125, 87,
            232, 80, 6, 232, 93,
        ]

        a = Autograph.Channel()
        b = Autograph.Channel()

        let aliceHello = try a.useKeyPairs(
            identityKeyPair: aliceIdentityKeyPair,
            ephemeralKeyPair: aliceEphemeralKeyPair
        )

        let bobHello = try b.useKeyPairs(
            identityKeyPair: bobIdentityKeyPair,
            ephemeralKeyPair: bobEphemeralKeyPair
        )

        a.usePublicKeys(publicKeys: bobHello)
        b.usePublicKeys(publicKeys: aliceHello)

        handshakeAlice = try a.keyExchange(isInitiator: true)
        handshakeBob = try b.keyExchange(isInitiator: false)

        try a.verifyKeyExchange(signature: handshakeBob)
        try b.verifyKeyExchange(signature: handshakeAlice)
    }

    // Should allow Alice and Bob to perform a key exchange
    func testKeyExchange() {
        XCTAssertEqual(handshakeAlice, aliceHandshake)
        XCTAssertEqual(handshakeBob, bobHandshake)
    }

    // Should calculate safety numbers correctly
    func testSafetyNumber() throws {
        let aliceSafetyNumber = try a.authenticate()
        let bobSafetyNumber = try b.authenticate()
        XCTAssertEqual(aliceSafetyNumber, safetyNumber)
        XCTAssertEqual(bobSafetyNumber, safetyNumber)
    }

    // Should allow Alice to send encrypted data to Bob
    func testAliceMessageToBob() throws {
        let (encryptIndex, message) = try a.encrypt(plaintext: data)
        let (decryptIndex, plaintext) = try b.decrypt(message: message)
        XCTAssertEqual(encryptIndex, 1)
        XCTAssertEqual(decryptIndex, 1)
        XCTAssertEqual(message, aliceMessage)
        XCTAssertEqual(plaintext, data)
    }

    // Should allow Bob to send encrypted data to Alice
    func testBobMessageToAlice() throws {
        let (_, message) = try b.encrypt(plaintext: data)
        let (_, plaintext) = try a.decrypt(message: message)
        XCTAssertEqual(message, bobMessage)
        XCTAssertEqual(plaintext, data)
    }

    // Should allow Bob to certify Alice's ownership of her identity key and
    // data
    func testBobCertifyAliceData() throws {
        let signature = try b.certifyData(data: data)
        XCTAssertEqual(signature, bobSignatureAliceData)
    }

    // Should allow Alice to certify Bob's ownership of his identity key and
    // data
    func testAliceCertifyBobData() throws {
        let signature = try a.certifyData(data: data)
        XCTAssertEqual(signature, aliceSignatureBobData)
    }

    // Should allow Bob to certify Alice's ownership of her identity key
    func testBobCertifyAliceIdentity() throws {
        let signature = try b.certifyIdentity()
        XCTAssertEqual(signature, bobSignatureAliceIdentity)
    }

    // Should allow Alice to certify Bob's ownership of his identity key
    func testAliceCertifyBobIdentity() throws {
        let signature = try a.certifyIdentity()
        XCTAssertEqual(signature, aliceSignatureBobIdentity)
    }

    // Should allow Bob to verify Alice's ownership of her identity key and data
    // based on Charlie's public key and signature
    func testBobVerifyAliceData() {
        let verified = b.verifyData(
            data: data,
            publicKey: charlieIdentityKey,
            signature: charlieSignatureAliceData
        )
        XCTAssertTrue(verified)
    }

    // Should allow Alice to verify Bob's ownership of his identity key and
    // ddata
    // based on Charlie's public key and signature
    func testAliceVerifyBobData() {
        let verified = a.verifyData(
            data: data,
            publicKey: charlieIdentityKey,
            signature: charlieSignatureBobData
        )
        XCTAssertTrue(verified)
    }

    // Should allow Bob to verify Alice's ownership of her identity key based on
    // Charlie's public key and signature
    func testBobVerifyAliceIdentity() {
        let verified = b.verifyIdentity(
            publicKey: charlieIdentityKey,
            signature: charlieSignatureAliceIdentity
        )
        XCTAssertTrue(verified)
    }

    // Should allow Alice to verify Bob's ownership of his identity key based on
    // Charlie's public key and signature
    func testAliceVerifyBobIdentity() {
        let verified = a.verifyIdentity(
            publicKey: charlieIdentityKey,
            signature: charlieSignatureBobIdentity
        )
        XCTAssertTrue(verified)
    }

    // Should handle out of order messages correctly
    func testOutOfOrderMessages() throws {
        let data1: Autograph.Bytes = [1, 2, 3]
        let data2: Autograph.Bytes = [4, 5, 6]
        let data3: Autograph.Bytes = [7, 8, 9]
        let data4: Autograph.Bytes = [10, 11, 12]
        let (_, message1) = try a.encrypt(plaintext: data1)
        let (_, message2) = try a.encrypt(plaintext: data2)
        let (_, message3) = try a.encrypt(plaintext: data3)
        let (_, message4) = try a.encrypt(plaintext: data4)
        let (index4, plaintext4) = try b.decrypt(message: message4)
        let (index2, plaintext2) = try b.decrypt(message: message2)
        let (index3, plaintext3) = try b.decrypt(message: message3)
        let (index1, plaintext1) = try b.decrypt(message: message1)
        XCTAssertEqual(index1, 1)
        XCTAssertEqual(index2, 2)
        XCTAssertEqual(index3, 3)
        XCTAssertEqual(index4, 4)
        XCTAssertEqual(plaintext1, data1)
        XCTAssertEqual(plaintext2, data2)
        XCTAssertEqual(plaintext3, data3)
        XCTAssertEqual(plaintext4, data4)
    }

    // Should handle sessions correctly
    func testSession() throws {
        var (key, ciphertext) = try a.close()
        try b.open(key: &key, ciphertext: ciphertext)
        let signature = try b.certifyIdentity()
        XCTAssertEqual(signature, aliceSignatureBobIdentity)
    }
}
