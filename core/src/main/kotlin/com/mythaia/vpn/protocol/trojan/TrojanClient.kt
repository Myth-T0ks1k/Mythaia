package com.mythaia.vpn.protocol.trojan

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.protocol.StreamTransports
import com.mythaia.vpn.protocol.tls.TlsError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.delay

private val logger = MythaiaLogger("TrojanClient")

/**
 * Client for establishing Trojan proxy connections.
 *
 * Trojan mandates TLS on the wire; the server inspects the SHA224 hash of the
 * password and falls back to its decoy HTTP site for anything that doesn't
 * match, so there is no plaintext or Reality variant. UDP rides the same TLS
 * stream via [TrojanUdpConnection]'s per-packet framing. Mux is not supported.
 *
 * Retry logic: 5 attempts with linear backoff 0/200/400/600/800ms.
 */
class TrojanClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): ProxyConnection {
        val password = requirePassword()
        val tlsConfig = requireTls()

        val opened = connectTransport(tlsConfig)
        val trojan = TrojanConnection(opened.transport, opened.tlsVersion, password, destinationHost, destinationPort)
        if (initialData != null && initialData.isNotEmpty()) {
            trojan.send(initialData)
        }
        return trojan
    }

    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): ProxyConnection {
        val password = requirePassword()
        val tlsConfig = requireTls()

        val opened = connectTransport(tlsConfig)
        return TrojanUdpConnection(opened.transport, opened.tlsVersion, password, destinationHost, destinationPort)
    }

    private fun requirePassword(): String {
        val password = configuration.trojanPassword
        if (password.isNullOrEmpty()) {
            throw ProxyError.ProtocolError("Trojan password not set")
        }
        return password
    }

    private fun requireTls(): TlsConfiguration {
        return configuration.trojanTls
            ?: throw ProxyError.ProtocolError("Trojan requires TLS configuration")
    }

    /**
     * Opens the mandatory TLS tunnel. Direct dials retry with linear backoff;
     * chained dials bubble the first failure up so the enclosing chain driver
     * can rebuild the upstream tunnel.
     */
    private suspend fun connectTransport(tlsConfig: TlsConfiguration): StreamTransports.Opened {
        if (tunnel != null) {
            return StreamTransports.open(configuration, tlsConfig, tunnel)
        }

        var lastError: Exception? = null
        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (attempt > 0) delay(RETRY_BASE_DELAY_MS * attempt)
            try {
                return StreamTransports.open(configuration, tlsConfig, null)
            } catch (e: Exception) {
                if (e is TlsError.CertificateValidationFailed) throw e
                logger.debug("Trojan TLS attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }
}
