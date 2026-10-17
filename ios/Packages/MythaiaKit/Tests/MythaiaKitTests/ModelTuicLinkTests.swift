import XCTest
@testable import MythaiaKit

/// `tuic://uuid:password@host:port`, the shape every TUIC client emits.
final class ModelTuicLinkTests: XCTestCase {

    private let uuid = "b1a2c3d4-0000-4000-8000-000000000001"

    func testALinkSplitsIntoAUuidAndAPassword() throws {
        let config = try ProxyConfiguration.fromUrl("tuic://\(uuid):hunter2@example.com:8443#Tokyo")
        XCTAssertEqual(config.outboundProtocol, .tuic)
        XCTAssertEqual(config.uuid, UUID(uuidString: uuid))
        XCTAssertEqual(config.password, "hunter2")
        XCTAssertEqual(config.serverAddress, "example.com")
        XCTAssertEqual(config.serverPort, 8443)
        XCTAssertEqual(config.name, "Tokyo")
    }

    func testALinkWithoutAPortTakes443() throws {
        XCTAssertEqual(try ProxyConfiguration.fromUrl("tuic://\(uuid):pw@example.com").serverPort, 443)
    }

    func testSniOverridesTheHostForTheCertificateName() throws {
        XCTAssertEqual(try ProxyConfiguration.fromUrl("tuic://\(uuid):pw@192.0.2.4:443?sni=example.com").tls?.serverName, "example.com")
    }

    func testAPercentEncodedPasswordSurvives() throws {
        XCTAssertEqual(try ProxyConfiguration.fromUrl("tuic://\(uuid):p%40ss%3Aword@example.com:443").password, "p@ss:word")
    }

    func testAPercentSignInThePasswordSurvivesTheRoundTrip() throws {
        // The userinfo is decoded once, by the link splitter; decoding the
        // password a second time turned "a%41b" into "aAb".
        let original = try ProxyConfiguration.fromUrl("tuic://\(uuid):a%2541b@example.com:443#N")
        XCTAssertEqual(original.password, "a%41b")
        XCTAssertEqual(try ProxyConfiguration.fromUrl(original.toUrl()).password, "a%41b")
    }

    func testALinkRoundTripsBackToItself() throws {
        let original = try ProxyConfiguration.fromUrl("tuic://\(uuid):hunter2@example.com:8443#Tokyo")
        let reparsed = try ProxyConfiguration.fromUrl(original.toUrl())
        XCTAssertEqual(reparsed.uuid, original.uuid)
        XCTAssertEqual(reparsed.password, original.password)
        XCTAssertEqual(reparsed.serverAddress, original.serverAddress)
        XCTAssertEqual(reparsed.serverPort, original.serverPort)
        XCTAssertEqual(reparsed.name, original.name)
        // The user part is written as every TUIC client writes a UUID: lower case.
        XCTAssertTrue(original.toUrl().hasPrefix("tuic://\(uuid):hunter2@example.com:8443"))
    }

    func testALinkWithNoPasswordIsRefused() {
        XCTAssertThrowsError(try ProxyConfiguration.fromUrl("tuic://\(uuid)@example.com:443")) { error in
            guard case MythaiaError.parse? = error as? MythaiaError else { return XCTFail("\(error)") }
        }
    }

    func testAUserPartThatIsNotAUuidIsRefused() {
        XCTAssertThrowsError(try ProxyConfiguration.fromUrl("tuic://not-a-uuid:pw@example.com:443")) { error in
            guard case MythaiaError.parse? = error as? MythaiaError else { return XCTFail("\(error)") }
        }
    }

    func testTheSchemeIsOneTheImporterRecognises() {
        XCTAssertTrue(ProxyConfiguration.canParseUrl("tuic://\(uuid):pw@example.com"))
    }
}
