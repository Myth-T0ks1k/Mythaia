import XCTest
@testable import MythaiaKit

final class ModelGrpcConfigurationTests: XCTestCase {

    func testTheServiceNameIsEscapedAsGosPathEscapeDoesSinceThatIsWhatTheServerExpects() {
        XCTAssertEqual(GrpcConfiguration(serviceName: "my@svc").resolvedPath(), "/my@svc/Tun")
        XCTAssertEqual(GrpcConfiguration(serviceName: "a b*").resolvedPath(), "/a%20b%2A/Tun")
        XCTAssertEqual(GrpcConfiguration(serviceName: "x/y").resolvedPath(), "/x%2Fy/Tun")
        // Unreserved and the sub-delims Go keeps in a path segment.
        XCTAssertEqual(
            GrpcConfiguration(serviceName: "~u.n-d_r$&+:=@", multiMode: true).resolvedPath(),
            "/~u.n-d_r$&+:=@/TunMulti"
        )
        // The sub-delims it does not, and UTF-8 byte by byte, uppercase.
        XCTAssertEqual(GrpcConfiguration(serviceName: "п;,?%").resolvedPath(), "/%D0%BF%3B%2C%3F%25/Tun")
    }

    func testACustomPathEscapesEachSegmentOnItsOwn() {
        XCTAssertEqual(GrpcConfiguration(serviceName: "/a b/c/Stream").resolvedPath(), "/a%20b/c/Stream")
        XCTAssertEqual(GrpcConfiguration(serviceName: "/svc/Tun|TunMulti").resolvedPath(), "/svc/Tun")
        XCTAssertEqual(GrpcConfiguration(serviceName: "/svc/Tun|TunMulti", multiMode: true).resolvedPath(), "/svc/TunMulti")
        // A lone leading slash, as Xray reads it: no service part, the rest from index 2.
        XCTAssertEqual(GrpcConfiguration(serviceName: "/Tun").resolvedPath(), "/un")
    }

    func testTheDefaultServiceNameIsUnchangedByEscaping() {
        XCTAssertEqual(GrpcConfiguration().resolvedPath(), "/\(GrpcConfiguration.defaultServiceName)/Tun")
    }

    func testTheAuthorityFallsBackThroughTheServerNames() {
        let empty = GrpcConfiguration()
        XCTAssertEqual(empty.resolvedAuthority(tlsServerName: "tls.example.com", realityServerName: nil, serverAddress: "192.0.2.1"), "tls.example.com")
        XCTAssertEqual(empty.resolvedAuthority(tlsServerName: nil, realityServerName: "r.example.com", serverAddress: "192.0.2.1"), "r.example.com")
        XCTAssertEqual(empty.resolvedAuthority(tlsServerName: "", realityServerName: nil, serverAddress: "192.0.2.1"), "192.0.2.1")
        XCTAssertEqual(GrpcConfiguration(authority: "a.example.com").resolvedAuthority(tlsServerName: "t", realityServerName: nil, serverAddress: "s"), "a.example.com")
    }

    func testALinksGrpcParametersAreRead() {
        let config = GrpcConfiguration.parse([
            "serviceName": "svc", "authority": "a.example.com", "mode": "MULTI",
            "idle_timeout": "60", "permit_without_stream": "1",
        ])
        XCTAssertEqual(config.serviceName, "svc")
        XCTAssertEqual(config.authority, "a.example.com")
        XCTAssertTrue(config.multiMode)
        XCTAssertEqual(config.idleTimeout, 60)
        XCTAssertTrue(config.permitWithoutStream)
    }
}
