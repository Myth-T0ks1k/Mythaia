package com.mythaia.vpn.mitm

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import java.math.BigInteger
import java.net.IDN
import java.net.InetAddress
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date

/**
 * The per-host certificates an intercepted client is shown.
 *
 * When a client opens `https://example.com` through the tunnel and the host is
 * one the user chose to intercept, the inner TLS handshake has to present a
 * certificate for `example.com` that the client will accept. This mints one —
 * signed by [MitmCertificateAuthority], naming the host in both the subject and
 * the subjectAltName — and keeps it for the next connection to the same host,
 * because a mint is a signature and a handshake is already expensive enough.
 *
 * Every leaf shares one private key, generated when the cache is. The key is
 * not what makes a leaf trustworthy — the CA's signature is — and a fresh key
 * per host would cost a key generation on every first connection for nothing.
 *
 * Leaves live for a week and are re-minted a day before they expire, so a
 * client never sees a certificate on its last hours. The cache holds 256
 * hosts and drops the least recently used one beyond that.
 *
 * Minting is pure given its inputs — the host, a serial, the times, the keys —
 * and [mint] is exposed as such so the tests can pin every field of the
 * result without going through the cache.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class MitmLeafCertificates(
    private val authority: MitmCertificateAuthority,
    /** The clock, injectable so expiry and eviction can be tested without waiting. */
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: SecureRandom = SecureRandom(),
    leafKeyPair: KeyPair = MitmCertificateAuthority.generateKeyPair(random)
) {

    /** What the inner handshake needs: the certificate to present and the key to prove it with. */
    class Leaf(
        val certificate: X509Certificate,
        val privateKey: PrivateKey,
        /** The `notAfter` of [certificate], kept so the cache need not parse it back out. */
        val expiresAtMillis: Long
    ) {
        /** The certificate as DER, the form the handshake sends. */
        val certificateDer: ByteArray
            get() = certificate.encoded
    }

    private class Entry(val leaf: Leaf, var lastAccessMillis: Long)

    private val leafKeyPair: KeyPair = leafKeyPair
    private val entries = HashMap<String, Entry>()
    private val lock = Any()

    /** How many hosts are cached right now; for tests of the eviction policy. */
    val cachedHostCount: Int
        get() = synchronized(lock) { entries.size }

    /**
     * The leaf for [host], minted if there is none or the one there is about
     * to expire.
     *
     * The host is lowercased first so `Example.COM` and `example.com` share a
     * leaf; SNI is case-insensitive and clients are not consistent about it.
     *
     * Minting happens outside the lock. Two connections racing on a new host
     * may both mint; the second overwrites the first, and both leaves are
     * valid, so the race costs one signature rather than a stall.
     *
     * @throws MitmCertificateAuthority.Failure when the leaf cannot be built.
     */
    fun leaf(host: String): Leaf {
        val normalized = host.lowercase()
        cached(normalized)?.let { return it }

        val minted = mintNow(normalized)
        synchronized(lock) {
            entries[normalized] = Entry(minted, clock())
            evictIfNeeded()
        }
        return minted
    }

    private fun cached(normalized: String): Leaf? = synchronized(lock) {
        val entry = entries[normalized] ?: return null
        val now = clock()
        if (entry.leaf.expiresAtMillis - now <= REFRESH_THRESHOLD_MILLIS) return null
        entry.lastAccessMillis = now
        entry.leaf
    }

    private fun mintNow(normalized: String): Leaf {
        val now = clock()
        val expiresAt = now + VALIDITY_MILLIS
        val certificate = mint(
            authority = authority,
            leafPublicKey = leafKeyPair.public,
            host = normalized,
            serial = MitmCertificateAuthority.randomSerial(random),
            notBeforeMillis = now - NOT_BEFORE_SKEW_MILLIS,
            notAfterMillis = expiresAt
        )
        return Leaf(certificate, leafKeyPair.private, expiresAt)
    }

    /** Drops the least recently used entries until the cache fits; called under [lock]. */
    private fun evictIfNeeded() {
        while (entries.size > MAX_ENTRIES) {
            val oldest = entries.entries.minByOrNull { it.value.lastAccessMillis } ?: return
            entries.remove(oldest.key)
        }
    }

    companion object {
        /** How many hosts are kept before the least recently used is dropped. */
        const val MAX_ENTRIES = 256

        /** How long a leaf is valid for: seven days. */
        const val VALIDITY_MILLIS = 7L * 24 * 60 * 60 * 1000

        /**
         * A leaf with less than this left is re-minted rather than reused.
         *
         * A connection can outlive its handshake by hours; handing out a
         * certificate that expires during the connection would make a client
         * that re-validates mid-stream fail for no reason it can report.
         */
        const val REFRESH_THRESHOLD_MILLIS = 24L * 60 * 60 * 1000

        /** How far into the past `notBefore` is set, for the same reason as the root's. */
        const val NOT_BEFORE_SKEW_MILLIS = MitmCertificateAuthority.NOT_BEFORE_SKEW_MILLIS

        /**
         * Builds the certificate for [host], signed by [authority], for whoever
         * holds the private half of [leafPublicKey].
         *
         * The subject names the host in its common name — with the URI
         * brackets stripped from an IPv6 literal, so it reads the same as the
         * subjectAltName — but it is the subjectAltName that clients match on,
         * and it is a `dNSName` for a name and an `iPAddress` for a literal:
         * Chrome and Safari refuse a `dNSName` holding an address.
         *
         * @throws MitmCertificateAuthority.Failure when the certificate cannot be built.
         */
        fun mint(
            authority: MitmCertificateAuthority,
            leafPublicKey: PublicKey,
            host: String,
            serial: BigInteger,
            notBeforeMillis: Long,
            notAfterMillis: Long
        ): X509Certificate {
            val subject = X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.O, MitmCertificateAuthority.ORGANIZATION)
                .addRDN(BCStyle.CN, stripBrackets(host))
                .build()

            return try {
                val extensions = JcaX509ExtensionUtils()
                val builder = JcaX509v3CertificateBuilder(
                    authority.subjectName, serial, Date(notBeforeMillis), Date(notAfterMillis),
                    subject, leafPublicKey
                )
                    .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
                    .addExtension(
                        Extension.extendedKeyUsage, false,
                        ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
                    )
                    .addExtension(
                        Extension.subjectKeyIdentifier, false,
                        extensions.createSubjectKeyIdentifier(leafPublicKey)
                    )
                    .addExtension(
                        Extension.authorityKeyIdentifier, false,
                        AuthorityKeyIdentifier(authority.subjectKeyIdentifier)
                    )
                    .addExtension(
                        Extension.subjectAlternativeName, false,
                        GeneralNames(subjectAltName(host))
                    )
                MitmCertificateAuthority.parseCertificate(builder.build(authority.contentSigner()).encoded)
            } catch (e: MitmCertificateAuthority.Failure) {
                throw e
            } catch (e: Exception) {
                throw MitmCertificateAuthority.Failure(
                    "could not build the leaf certificate for '$host': ${e.message ?: e}", e
                )
            }
        }

        /**
         * The single subjectAltName entry for [host].
         *
         * A `dNSName` is an IA5String, so a name with characters outside ASCII
         * is converted to its IDNA A-label first — a client matches the
         * A-label it put in SNI, and a raw U-label would never match.
         */
        fun subjectAltName(host: String): GeneralName {
            val address = ipAddressBytes(host)
            if (address != null) {
                return GeneralName(GeneralName.iPAddress, DEROctetString(address))
            }
            return GeneralName(GeneralName.dNSName, idnaAscii(host))
        }

        /**
         * The 4 or 16 network-order bytes of [host] when it is an IP literal,
         * otherwise null.
         *
         * SNI carries an IPv6 literal in brackets, which are stripped. A zone
         * identifier (`%en0`) has no place in a certificate and makes the
         * whole thing a name. Only a canonical dotted quad is an IPv4 literal:
         * `1.2.3` is an `inet_aton` shorthand that is also a legal hostname,
         * and encoding it as an address would mint a certificate no client
         * accepts.
         */
        fun ipAddressBytes(host: String): ByteArray? {
            val bare = stripBrackets(host)
            if (bare.contains('%')) return null

            if (isDottedQuad(bare)) {
                return bare.split('.').map { it.toInt().toByte() }.toByteArray()
            }
            if (bare.contains(':') && bare.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
                // A string of hex digits, colons and dots is never a resolvable
                // name, so this cannot turn into a DNS lookup; the platform
                // parser rejects a malformed literal without one.
                return try {
                    InetAddress.getByName(bare).address.takeIf { it.size == 16 }
                } catch (_: Exception) {
                    null
                }
            }
            return null
        }

        /** True only for four decimal octets of one to three digits each, all at most 255. */
        internal fun isDottedQuad(text: String): Boolean {
            val parts = text.split('.')
            if (parts.size != 4) return false
            return parts.all { part ->
                part.length in 1..3 && part.all { it in '0'..'9' } && part.toInt() <= 255
            }
        }

        /**
         * The A-label form of [host], or [host] itself when it is already
         * ASCII or the conversion refuses it.
         *
         * A refused name is handed through unchanged rather than dropped: the
         * leaf then fails to match and the client reports a certificate error
         * for that host, which is the honest outcome.
         */
        internal fun idnaAscii(host: String): String {
            if (host.all { it.code < 0x80 }) return host
            return try {
                IDN.toASCII(host, IDN.ALLOW_UNASSIGNED)
            } catch (_: Exception) {
                host
            }
        }

        private fun stripBrackets(host: String): String =
            if (host.length >= 2 && host.startsWith('[') && host.endsWith(']')) {
                host.substring(1, host.length - 1)
            } else {
                host
            }
    }
}
