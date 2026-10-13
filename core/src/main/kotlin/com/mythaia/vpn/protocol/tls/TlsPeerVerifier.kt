package com.mythaia.vpn.protocol.tls

import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Deciding whether the peer on the other end is who it claims to be.
 *
 * Three separate questions, all of which have to be answered yes: does a
 * recognised authority vouch for this certificate, is it valid for the name we
 * asked for, and does the peer actually hold its private key. Skip the first
 * two and any certificate will do; skip the third and anyone can replay
 * somebody else's.
 *
 * It lives on its own because two handshakes need it — the record-layer client
 * next door and the QUIC one — and certificate validation is the last thing
 * that should exist in two copies, since the copy that quietly stops being
 * called is not a bug anybody sees.
 */
object TlsPeerVerifier {

    /** Why verification failed, in terms a log line can use. */
    class Failure(message: String) : Exception(message)

    /**
     * Parses a DER chain, in the order the peer sent it.
     *
     * @throws Failure when any certificate in it is not X.509.
     */
    fun parseChain(der: List<ByteArray>): List<X509Certificate> {
        if (der.isEmpty()) throw Failure("peer sent no certificate")
        val factory = try {
            CertificateFactory.getInstance("X.509")
        } catch (e: Exception) {
            throw Failure("no X.509 support: ${e.message ?: e}")
        }
        return der.map {
            try {
                factory.generateCertificate(it.inputStream()) as X509Certificate
            } catch (e: Exception) {
                throw Failure("certificate did not parse: ${e.message ?: e}")
            }
        }
    }

    /**
     * Checks the chain against the system store and the name against the
     * certificate, falling back to a fingerprint the user pinned themselves.
     *
     * @throws Failure when neither the system nor the user vouches for it.
     */
    fun verifyTrust(chain: List<X509Certificate>, serverName: String) {
        val leaf = chain.first()
        try {
            leaf.checkValidity()

            val trust = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(null as KeyStore?) }
                .trustManagers
                .filterIsInstance<X509TrustManager>()
                .firstOrNull() ?: throw Failure("no system trust manager")

            val authType = if (leaf.publicKey.algorithm == "EC") "ECDHE_ECDSA" else "ECDHE_RSA"
            trust.checkServerTrusted(chain.toTypedArray(), authType)
            verifyHostname(leaf, serverName)
        } catch (e: Exception) {
            if (!isUserTrusted(leaf)) {
                throw Failure("certificate not trusted by the system or the user: ${e.message ?: e}")
            }
        }
    }

    /**
     * Whether the peer signed the transcript with the certificate's key.
     *
     * This is what makes the certificate mean anything: without it a peer could
     * present any valid certificate it had seen and still not hold the key.
     * The signed content is RFC 8446 §4.4.3 — 64 spaces, a context label, a
     * zero byte, then the transcript hash.
     */
    fun verifySignature(
        certificate: X509Certificate,
        algorithm: Int,
        signature: ByteArray,
        transcriptHash: ByteArray
    ): Boolean {
        val content = ByteArray(64) { 0x20 } +
            "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0x00) +
            transcriptHash

        return try {
            signature(algorithm).run {
                initVerify(certificate.publicKey)
                update(content)
                verify(signature)
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * The name on the certificate against the name we asked for.
     *
     * Only subjectAltName counts; the common name has not been a legitimate
     * source for this since RFC 2818 was replaced, and honouring it is how a
     * certificate for one name gets accepted for another.
     */
    fun verifyHostname(certificate: X509Certificate, serverName: String) {
        if (serverName.isEmpty()) return

        val isIpLiteral = serverName.matches(Regex("^[0-9.]+$")) || serverName.contains(":")
        val names = certificate.subjectAlternativeNames ?: emptyList<List<*>>()

        for (entry in names) {
            if (entry == null || entry.size < 2) continue
            val type = (entry[0] as? Int) ?: continue
            when {
                !isIpLiteral && type == 2 -> {
                    val dnsName = (entry[1] as? String) ?: continue
                    if (matchesDnsName(serverName, dnsName)) return
                }
                isIpLiteral && type == 7 -> {
                    val ip = (entry[1] as? String) ?: continue
                    try {
                        if (java.net.InetAddress.getByName(ip) ==
                            java.net.InetAddress.getByName(serverName)
                        ) return
                    } catch (_: Exception) {
                        // Not an address we can compare; keep looking.
                    }
                }
            }
        }
        throw Failure("certificate is not valid for '$serverName'")
    }

    /**
     * Wildcard matching, left-most label only.
     *
     * `*.example.com` covers `a.example.com` and not `a.b.example.com`, and
     * never the bare `example.com` — a wildcard that matched its own parent
     * would let a certificate for a subdomain stand in for the site itself.
     */
    fun matchesDnsName(serverName: String, certificateName: String): Boolean {
        // Certificates carry A-labels; a name typed with non-ASCII letters is
        // compared in that form too.
        val host = runCatching { java.net.IDN.toASCII(serverName) }.getOrDefault(serverName)
            .lowercase().trimEnd('.')
        val pattern = certificateName.lowercase().trimEnd('.')
        if (pattern.isEmpty()) return false
        if (!pattern.startsWith("*.")) return host == pattern

        val suffix = pattern.substring(1)          // ".example.com"
        if (!host.endsWith(suffix)) return false
        val label = host.dropLast(suffix.length)
        return label.isNotEmpty() && !label.contains('.')
    }

    /**
     * Whether the user pinned this exact certificate.
     *
     * Every entry is compared, without stopping at the first match, so the time
     * taken does not depend on where in the list a match sits.
     */
    /** Whether [certificate]'s SHA-256 is one of [pins] (lowercase hex). */
    fun matchesPin(certificate: X509Certificate, pins: List<String>): Boolean {
        val candidate = MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
            .toByteArray(Charsets.US_ASCII)
        var matched = false
        for (pin in pins) {
            if (constantTimeEqual(candidate, pin.lowercase().toByteArray(Charsets.US_ASCII))) matched = true
        }
        return matched
    }

    fun isUserTrusted(certificate: X509Certificate): Boolean {
        val trusted = CertificatePolicy.trustedFingerprints
        if (trusted.isEmpty()) return false

        val candidate = MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
            .toByteArray(Charsets.US_ASCII)

        var matched = false
        for (entry in trusted) {
            if (constantTimeEqual(candidate, entry.toByteArray(Charsets.US_ASCII))) matched = true
        }
        return matched
    }

    private fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var difference = 0
        for (i in a.indices) difference = difference or (a[i].toInt() xor b[i].toInt())
        return difference == 0
    }

    /**
     * The JCA name for a TLS signature algorithm.
     *
     * Conscrypt spells PSS as `SHA256withRSA/PSS`; the generic `RSASSA-PSS`
     * needs explicit parameters it will not infer.
     */
    /**
     * A verifier for a TLS signature scheme, ready for `initVerify`.
     *
     * Conscrypt (Android) knows RSA-PSS as `SHA256withRSA/PSS`; the desktop
     * JDK has no such name and only `RSASSA-PSS`, which takes its digest,
     * MGF1 digest and salt length as parameters instead of inferring them.
     * Without this fallback the Windows build failed every TLS 1.3 server
     * with an RSA certificate — most of them, CloudFront included.
     */
    fun signature(tlsAlgorithm: Int): Signature {
        val name = javaSignatureAlgorithm(tlsAlgorithm)
        return try {
            Signature.getInstance(name)
        } catch (e: java.security.NoSuchAlgorithmException) {
            val digest = when (tlsAlgorithm) {
                0x0804, 0x0809 -> "SHA-256"
                0x0805, 0x080a -> "SHA-384"
                0x0806, 0x080b -> "SHA-512"
                else -> throw e
            }
            val saltLength = when (digest) { "SHA-256" -> 32; "SHA-384" -> 48; else -> 64 }
            Signature.getInstance("RSASSA-PSS").apply {
                setParameter(
                    java.security.spec.PSSParameterSpec(
                        digest, "MGF1", java.security.spec.MGF1ParameterSpec(digest), saltLength, 1
                    )
                )
            }
        }
    }

    fun javaSignatureAlgorithm(tlsAlgorithm: Int): String = when (tlsAlgorithm) {
        0x0403 -> "SHA256withECDSA"
        0x0503 -> "SHA384withECDSA"
        0x0603 -> "SHA512withECDSA"
        0x0804 -> "SHA256withRSA/PSS"
        0x0805 -> "SHA384withRSA/PSS"
        0x0806 -> "SHA512withRSA/PSS"
        0x0401 -> "SHA256withRSA"
        0x0501 -> "SHA384withRSA"
        0x0601 -> "SHA512withRSA"
        0x0201 -> "SHA1withRSA"
        0x0807 -> "Ed25519"
        0x0808 -> "Ed448"
        0x0809 -> "SHA256withRSA/PSS"
        0x080a -> "SHA384withRSA/PSS"
        0x080b -> "SHA512withRSA/PSS"
        // A scheme this table does not know must not be verified as if it
        // were PKCS#1 SHA-256: the check would fail honestly at best and, with
        // a matching key, pass a signature made under different rules.
        else -> throw java.security.NoSuchAlgorithmException(
            "unsupported TLS signature scheme 0x" + tlsAlgorithm.toString(16)
        )
    }
}
