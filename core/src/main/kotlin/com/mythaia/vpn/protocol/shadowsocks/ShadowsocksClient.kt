package com.mythaia.vpn.protocol.shadowsocks

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.util.NioSocket
import kotlinx.coroutines.delay

private val logger = MythaiaLogger("ShadowsocksClient")

/**
 * Shadowsocks proxy client. Supports legacy AEAD ciphers, Shadowsocks 2022, and proxy chaining.
 */
class ShadowsocksClient(
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
        val method = configuration.ssMethod
            ?: throw ProxyError.ProtocolError("Shadowsocks method not configured")
        val password = configuration.ssPassword
            ?: throw ProxyError.ProtocolError("Shadowsocks password not configured")

        val cipher = ShadowsocksCipher.fromMethod(method)
            ?: throw ShadowsocksError.InvalidMethod(method)

        var lastError: Exception? = null

        for (attempt in 1..MAX_RETRY_ATTEMPTS) {
            if (attempt > 1) {
                delay(RETRY_BASE_DELAY_MS * (attempt - 1))
            }

            var transport: Transport? = null
            try {
                transport = connectTransport()
                val addressHeader = ShadowsocksProtocol.buildAddressHeader(destinationHost, destinationPort)

                val connection = if (cipher.isSS2022) {
                    val pskList = ShadowsocksKeyDerivation.decodePSKList(password, cipher.keySize)
                        ?: throw ShadowsocksError.InvalidPSK()
                    Shadowsocks2022Connection(transport, cipher, pskList, addressHeader)
                } else {
                    val masterKey = ShadowsocksKeyDerivation.deriveKey(password, cipher.keySize)
                    ShadowsocksConnection(transport, cipher, masterKey, addressHeader)
                }

                // The address header rides the first write, so it goes out now
                // even when the app has sent nothing: a server-speaks-first
                // protocol (SSH, SMTP, IMAP, MySQL) never gets its banner until
                // the server knows where to connect. A chunk carrying only the
                // header is valid AEAD, and 2022 pads an empty initial payload.
                // The tunnel has already waited for the app's first bytes and
                // acks them itself once this returns.
                connection.send(initialData ?: ByteArray(0))

                return connection
            } catch (e: Exception) {
                // Nothing else holds a transport that never became a returned
                // connection, so a failed attempt would otherwise leak it.
                runCatching { transport?.forceCancel() }
                if (e is com.mythaia.vpn.protocol.tls.TlsError.CertificateValidationFailed) throw e
                lastError = e
                logger.debug("Connect attempt $attempt failed: ${e.message}")
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts exhausted")
    }

    fun cancel() {
        // Lifecycle is owned by the returned connection.
    }

    /**
     * Direct NioSocket or a tunnel through an existing proxy connection. Uses
     * [ProxyConfiguration.serverAddress] for the direct socket so DNS refresh
     * happens naturally via [DnsCache].
     */
    private suspend fun connectTransport(): Transport {
        if (tunnel != null) {
            return TunneledTransport(tunnel)
        }

        val socket = NioSocket()
        socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
        return socket
    }
}
