package com.mythaia.vpn.mitm

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Calendar
import java.util.Date
import java.util.TimeZone

/**
 * The root certificate every intercepted HTTPS connection chains to.
 *
 * Intercepting HTTPS only works for clients that trust this certificate, so
 * its whole job is to be something the user can install once and forget: an
 * EC P-256 key, a self-signed certificate that says `CA:true` and nothing
 * else, and a validity long enough that nobody has to install it twice. The
 * name is fixed so that the entry the user sees in the system trust list is
 * recognisable — and so a regenerated authority replaces the old one under
 * the same name rather than piling up beside it.
 *
 * The private key never leaves the device and signs every leaf, which is why
 * this type holds it rather than handing it around: [MitmLeafCertificates]
 * asks the authority for a signer, not for the key.
 *
 * Nothing here touches Android. The authority is loaded from and saved to two
 * byte arrays — a PKCS#8 private key and a DER certificate — so the storage
 * layer can be whatever it needs to be on a device, and a desktop test can
 * exercise every path with nothing but bytes.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class MitmCertificateAuthority private constructor(
    /** The signing key; kept private to the authority, see the class note. */
    private val privateKey: PrivateKey,
    /** The self-signed root certificate. */
    val certificate: X509Certificate
) {

    /** Why an authority could not be built or loaded, in terms a log line can use. */
    class Failure(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** The root certificate as DER, which is what the user installs. */
    val certificateDer: ByteArray
        get() = certificate.encoded

    /**
     * The private key as PKCS#8 DER, for the storage layer.
     *
     * Together with [certificateDer] this is everything [load] needs to bring
     * the same authority back.
     */
    val privateKeyPkcs8: ByteArray
        get() = privateKey.encoded

    /**
     * The root certificate as PEM, for the user who would rather have text.
     *
     * Android's certificate installer takes either form; a PEM file survives
     * being pasted into a chat or an email, which DER does not.
     */
    fun certificatePem(): String {
        val body = Base64.getMimeEncoder(PEM_LINE_LENGTH, "\n".toByteArray(Charsets.US_ASCII))
            .encodeToString(certificateDer)
        return "$PEM_HEADER\n$body\n$PEM_FOOTER\n"
    }

    /**
     * The subject of the root certificate, byte for byte as it was encoded.
     *
     * A leaf's issuer must match the CA's subject exactly or chain building
     * fails, and re-encoding a name is the classic way to be one byte off.
     */
    internal val subjectName: X500Name
        get() = X500Name.getInstance(certificate.subjectX500Principal.encoded)

    /**
     * The subject key identifier of the root certificate, for a leaf's
     * authority key identifier.
     *
     * Falls back to computing one from the public key when the certificate
     * carries no such extension, which only happens for a certificate this
     * class did not generate.
     */
    internal val subjectKeyIdentifier: ByteArray
        get() {
            val holder = X509CertificateHolder(certificate.encoded)
            val extension = holder.getExtension(Extension.subjectKeyIdentifier)
            if (extension != null) {
                return ASN1OctetString.getInstance(extension.parsedValue).octets
            }
            return JcaX509ExtensionUtils().createSubjectKeyIdentifier(certificate.publicKey).keyIdentifier
        }

    /** A fresh signer over the CA key; one per certificate, they are not reusable. */
    internal fun contentSigner(): ContentSigner =
        JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(privateKey)

    companion object {
        /** The name the user sees in the trust list; stable across regeneration. */
        const val COMMON_NAME = "Mythaia Root Certificate"

        /** The organisation on both the root and every leaf. */
        const val ORGANIZATION = "Mythaia"

        /**
         * ecdsa-with-SHA256, for the root's self-signature and every leaf.
         *
         * P-256 with SHA-256 is what every TLS client accepts and what the
         * platform crypto on both the device and a test JVM implements
         * natively, so no provider has to be registered for it.
         */
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /** The curve of the CA key and of every leaf key. */
        const val CURVE = "secp256r1"

        /** How many calendar years the root is valid for. */
        const val VALIDITY_YEARS = 10

        /**
         * How far into the past `notBefore` is set.
         *
         * A device whose clock runs a little ahead of the one that minted the
         * certificate would otherwise reject it as not yet valid.
         */
        const val NOT_BEFORE_SKEW_MILLIS = 60L * 60 * 1000

        /**
         * The size of a serial number.
         *
         * Random rather than a counter: a serial only has to be unique per
         * issuer, and 128 random bits are unique without anyone having to
         * remember what was issued last — which matters when two processes
         * share the same key, as they do on the reference platform.
         */
        const val SERIAL_BYTES = 16

        /** The line length PEM readers expect. */
        private const val PEM_LINE_LENGTH = 64
        private const val PEM_HEADER = "-----BEGIN CERTIFICATE-----"
        private const val PEM_FOOTER = "-----END CERTIFICATE-----"

        /**
         * Generates a new authority valid from an hour before [nowMillis].
         *
         * @throws Failure when the platform cannot produce the key or the
         *   certificate, which on a supported device it always can.
         */
        fun generate(
            nowMillis: Long = System.currentTimeMillis(),
            random: SecureRandom = SecureRandom()
        ): MitmCertificateAuthority {
            val keyPair = generateKeyPair(random)
            val name = X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.O, ORGANIZATION)
                .addRDN(BCStyle.CN, COMMON_NAME)
                .build()

            val notBefore = Date(nowMillis - NOT_BEFORE_SKEW_MILLIS)
            val notAfter = Date(validityEnd(nowMillis))

            val certificate = try {
                val extensions = JcaX509ExtensionUtils()
                val builder = JcaX509v3CertificateBuilder(
                    name, randomSerial(random), notBefore, notAfter, name, keyPair.public
                )
                    // pathLen 0: this CA issues leaves and nothing below them,
                    // and a client that honours the constraint will refuse a
                    // sub-CA minted with a leaked key.
                    .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
                    .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
                    .addExtension(
                        Extension.subjectKeyIdentifier, false,
                        extensions.createSubjectKeyIdentifier(keyPair.public)
                    )
                val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.private)
                parseCertificate(builder.build(signer).encoded)
            } catch (e: Exception) {
                throw Failure("could not build the root certificate: ${e.message ?: e}", e)
            }
            return MitmCertificateAuthority(keyPair.private, certificate)
        }

        /**
         * Brings an authority back from what [privateKeyPkcs8] and
         * [certificateDer] saved.
         *
         * Fails closed: the certificate must parse, must be a CA, must verify
         * under its own key, and the private key must be the one that
         * certificate is for. An authority that passed anything less would
         * mint leaves that no client accepts, and the failure would show up as
         * an unexplained handshake error on some other host.
         *
         * @throws Failure when any of that does not hold.
         */
        fun load(privateKeyPkcs8: ByteArray, certificateDer: ByteArray): MitmCertificateAuthority {
            val certificate = try {
                parseCertificate(certificateDer)
            } catch (e: Exception) {
                throw Failure("the root certificate did not parse: ${e.message ?: e}", e)
            }
            val privateKey = try {
                KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privateKeyPkcs8))
            } catch (e: Exception) {
                throw Failure("the root private key did not parse: ${e.message ?: e}", e)
            }

            if (certificate.basicConstraints < 0) {
                throw Failure("the root certificate is not a certificate authority")
            }
            try {
                certificate.verify(certificate.publicKey)
            } catch (e: Exception) {
                throw Failure("the root certificate is not self-signed: ${e.message ?: e}", e)
            }
            if (!keyMatches(privateKey, certificate)) {
                throw Failure("the root private key does not belong to the root certificate")
            }
            return MitmCertificateAuthority(privateKey, certificate)
        }

        /**
         * A fresh P-256 pair, for the authority and for the shared leaf key.
         *
         * @throws Failure when the platform has no EC support.
         */
        internal fun generateKeyPair(random: SecureRandom): KeyPair = try {
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec(CURVE), random)
                generateKeyPair()
            }
        } catch (e: Exception) {
            throw Failure("could not generate a P-256 key: ${e.message ?: e}", e)
        }

        /**
         * A random positive serial of [SERIAL_BYTES] bytes.
         *
         * RFC 5280 §4.1.2.2 forbids zero, so the one draw in 2^128 that would
         * produce it becomes one instead.
         */
        internal fun randomSerial(random: SecureRandom): BigInteger {
            val bytes = ByteArray(SERIAL_BYTES)
            random.nextBytes(bytes)
            val serial = BigInteger(1, bytes)
            return if (serial.signum() == 0) BigInteger.ONE else serial
        }

        /**
         * [VALIDITY_YEARS] calendar years after [nowMillis].
         *
         * Calendar years rather than a fixed number of days so the expiry
         * lands on the same date, the way the reference computes it.
         */
        internal fun validityEnd(nowMillis: Long): Long {
            val calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
            calendar.timeInMillis = nowMillis
            calendar.add(Calendar.YEAR, VALIDITY_YEARS)
            return calendar.timeInMillis
        }

        /** DER to the platform's certificate type, the same way the TLS verifier does it. */
        internal fun parseCertificate(der: ByteArray): X509Certificate =
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

        /**
         * Whether [privateKey] is the private half of the certificate's key.
         *
         * A signature round trip is the one check that needs no curve
         * arithmetic and no provider: if the certificate's public key verifies
         * what this key signed, they are a pair.
         */
        private fun keyMatches(privateKey: PrivateKey, certificate: X509Certificate): Boolean = try {
            val probe = "mythaia-ca-key-check".toByteArray(Charsets.US_ASCII)
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initSign(privateKey)
                update(probe)
                sign()
            }
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(certificate.publicKey)
                update(probe)
                verify(signature)
            }
        } catch (_: Exception) {
            false
        }
    }
}
