import CryptoKit
import Foundation
import XCTest
@testable import MythaiaKit

/// Every server of the interop lab (scripts/lab, docs/TESTING.md) through the
/// Swift core: a hashed HTTP download and a UDP echo per link, against the
/// Xray and sing-box reference servers. Runs only with `MYTHAIA_LAB_LINKS`
/// naming the lab's link files (separated by ';'); the CI's lab job starts
/// the servers and sets it.
///
/// Each line of the result is printed as `LAB <name> <protocol> <http> <udp>`
/// and written to `MYTHAIA_LAB_OUT` when set. Protocols the Swift core does
/// not dial yet (QUIC, WireGuard ...) are reported, not failed; a protocol it
/// does dial must work, or the test fails.
final class LabInteropTests: XCTestCase {
    private struct Header {
        var host = "127.0.0.1"
        var port: UInt16 = 8099
        var path = "/blob"
        var sha = ""
        var udpHost = "127.0.0.1"
        var udpPort: UInt16 = 9053
        var insecure = false
    }

    func testEveryLabServer() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let list = env["MYTHAIA_LAB_LINKS"], !list.isEmpty else {
            throw XCTSkip("MYTHAIA_LAB_LINKS not set")
        }
        var lines: [String] = []
        var failures: [String] = []
        for path in list.split(separator: ";").map(String.init) where !path.isEmpty {
            let text = try String(contentsOfFile: path, encoding: .utf8)
            let header = Self.header(of: text)
            CertificatePolicy.setAllowInsecure(header.insecure)
            for raw in text.split(separator: "\n").map(String.init) {
                let link = raw.trimmingCharacters(in: .whitespaces)
                if link.isEmpty || link.hasPrefix("#") { continue }
                let result = await Self.probe(link: link, header: header)
                let line = "LAB\t\(result.name)\t\(result.protocolName)\t\(result.http)\t\(result.udp)"
                print(line)
                lines.append(line)
                if result.mustWork && !result.http.hasPrefix("OK") {
                    failures.append("\(result.name): \(result.http)")
                }
            }
        }
        CertificatePolicy.setAllowInsecure(false)
        if let out = env["MYTHAIA_LAB_OUT"] {
            try (lines.joined(separator: "\n") + "\n").write(toFile: out, atomically: true, encoding: .utf8)
        }
        XCTAssertTrue(failures.isEmpty, "Servers the Swift core dials but could not use:\n" + failures.joined(separator: "\n"))
    }

    private struct Result {
        var name: String
        var protocolName: String
        var http: String
        var udp: String
        var mustWork: Bool
    }

    private static func probe(link: String, header: Header) async -> Result {
        let configuration: ProxyConfiguration
        do {
            var parsed = try ProxyConfiguration.fromUrl(link)
            // The lab writes the emulator's name for the host machine.
            if parsed.serverAddress == "10.0.2.2" { parsed.serverAddress = "127.0.0.1" }
            configuration = parsed
        } catch {
            return Result(name: String(link.prefix(40)) + "…", protocolName: "?", http: "PARSE \(error.localizedDescription)", udp: "-", mustWork: true)
        }
        let label = configuration.name
        let protocolName = configuration.outboundProtocol.displayName
        let http: String
        var mustWork = true
        do {
            let started = Date()
            let stream = try await Dialer.connect(configuration, to: Endpoint(host: header.host, port: header.port), timeout: 15)
            let request = "GET \(header.path) HTTP/1.1\r\nHost: \(header.host):\(header.port)\r\nConnection: close\r\n\r\n"
            try await stream.send(Data(request.utf8))
            let body = try await withTimeout(30, "download") { try await readBody(stream) }
            stream.close()
            let digest = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            http = digest == header.sha ? "OK \(ms)ms \(body.count / 1024)KB" : "BAD HASH \(body.count) bytes"
        } catch let error as MythaiaError {
            if case .unsupported = error { mustWork = false }
            http = "FAIL \(error.localizedDescription)"
        } catch {
            http = "FAIL \(error.localizedDescription)"
        }
        let udp: String
        do {
            let flow = try await Dialer.connectUDP(configuration, to: Endpoint(host: header.udpHost, port: header.udpPort), timeout: 15)
            let payload = Data("mythaia-udp-\(UUID().uuidString)".utf8)
            try await flow.send(payload)
            let echo = try await withTimeout(5, "udp echo") { try await flow.receive() }
            flow.close()
            udp = echo == payload ? "OK echo" : "BAD echo"
        } catch {
            udp = "n/a \(error.localizedDescription)"
        }
        return Result(name: label, protocolName: protocolName, http: http, udp: udp, mustWork: mustWork)
    }

    /// The body of an HTTP/1.1 response read to the end of the stream
    /// (`Connection: close`), with Content-Length honoured when present.
    private static func readBody(_ stream: ByteStream) async throws -> Data {
        let reader = StreamReader(stream)
        let head = try await reader.readThrough(Data("\r\n\r\n".utf8))
        let headText = String(decoding: head, as: UTF8.self)
        guard headText.hasPrefix("HTTP/1.1 200") || headText.hasPrefix("HTTP/1.0 200") else {
            throw MythaiaError.protocolError(String(headText.prefix(40)))
        }
        var length: Int?
        for line in headText.split(separator: "\r\n") where line.lowercased().hasPrefix("content-length:") {
            length = Int(line.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces))
        }
        var body = Data()
        while length == nil || body.count < length! {
            guard let chunk = try await reader.readSome() else { break }
            body.append(chunk)
        }
        return body
    }

    /// `#http 127.0.0.1:8099/blob <sha>`, `#udp 127.0.0.1:9053 echo`, `#insecure`.
    private static func header(of text: String) -> Header {
        var header = Header()
        for line in text.split(separator: "\n") where line.hasPrefix("#") {
            let parts = line.dropFirst().split(separator: " ").map(String.init)
            guard let key = parts.first else { continue }
            switch key {
            case "http" where parts.count >= 3:
                let target = parts[1]
                let slash = target.firstIndex(of: "/") ?? target.endIndex
                let hostPort = String(target[..<slash])
                header.path = slash < target.endIndex ? String(target[slash...]) : "/"
                if let colon = hostPort.lastIndex(of: ":") {
                    header.host = String(hostPort[..<colon])
                    header.port = UInt16(hostPort[hostPort.index(after: colon)...]) ?? 80
                }
                header.sha = parts[2]
            case "udp" where parts.count >= 2:
                if let colon = parts[1].lastIndex(of: ":") {
                    header.udpHost = String(parts[1][..<colon])
                    header.udpPort = UInt16(parts[1][parts[1].index(after: colon)...]) ?? 9053
                }
            case "insecure":
                header.insecure = true
            default:
                break
            }
        }
        return header
    }
}
