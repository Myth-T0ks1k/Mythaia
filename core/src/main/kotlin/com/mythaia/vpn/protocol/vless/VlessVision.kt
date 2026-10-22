package com.mythaia.vpn.protocol.vless

import com.mythaia.data.model.ProxyError
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import kotlin.math.max
import kotlin.math.min

enum class VisionCommand(val value: Byte) {
    PADDING_CONTINUE(0x00),
    PADDING_END(0x01),
    PADDING_DIRECT(0x02);

    companion object {
        fun fromByte(b: Byte): VisionCommand? = entries.find { it.value == b }
    }
}

private val TLS_CLIENT_HANDSHAKE_START = byteArrayOf(0x16, 0x03)
private val TLS_SERVER_HANDSHAKE_START = byteArrayOf(0x16, 0x03, 0x03)
private val TLS_APPLICATION_DATA_START = byteArrayOf(0x17, 0x03, 0x03)
private val TLS13_SUPPORTED_VERSIONS = byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
private const val TLS_HANDSHAKE_TYPE_CLIENT_HELLO: Byte = 0x01
private const val TLS_HANDSHAKE_TYPE_SERVER_HELLO: Byte = 0x02

/** TLS 1.3 cipher suites that support XTLS direct copy. 0x1305 is intentionally excluded. */
private val TLS13_CIPHER_SUITES = setOf<Int>(
    0x1301,  // TLS_AES_128_GCM_SHA256
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256
    0x1304,  // TLS_AES_128_CCM_SHA256
)

class VisionTrafficState(
    val userUUID: ByteArray,
    testseed: IntArray = intArrayOf(900, 500, 900, 256)
) {
    val testseed: IntArray = if (testseed.size >= 4) testseed else intArrayOf(900, 500, 900, 256)

    var numberOfPacketsToFilter: Int = 8
    var enableXtls: Boolean = false
    var isTLS12orAbove: Boolean = false
    var isTLS: Boolean = false
    var cipher: Int = 0
    var remainingServerHello: Int = -1

    var writerIsPadding: Boolean = true
    var writerDirectCopy: Boolean = false

    var readerWithinPaddingBuffers: Boolean = true
    var readerDirectCopy: Boolean = false
    var remainingCommand: Int = -1
    var remainingContent: Int = -1
    var remainingPadding: Int = -1
    var currentCommand: Int = 0

    /** UUID prepended on the first packet only; cleared after first emit. */
    var writeOnceUserUUID: ByteArray? = userUUID.copyOf()
}

private const val VISION_BUF_SIZE = 8192

/** Buffers >= this need splitting to leave room for the 21-byte padding header. */
private const val RESHAPE_THRESHOLD = 8192 - 21  // 8171

/**
 * Recursively splits oversized data into chunks that each fit within
 * [RESHAPE_THRESHOLD]. Splits at the last TLS application data boundary when
 * possible; otherwise splits at the midpoint.
 */
private fun reshapeData(data: ByteArray): List<ByteArray> {
    if (data.size < RESHAPE_THRESHOLD) return listOf(data)

    var splitIndex = data.size / 2
    for (i in (data.size - 3) downTo 0) {
        if (data[i] == 0x17.toByte() && data[i + 1] == 0x03.toByte() && data[i + 2] == 0x03.toByte()) {
            if (i in 21..RESHAPE_THRESHOLD) {
                splitIndex = i
                break
            }
        }
    }

    val first = data.copyOfRange(0, splitIndex)
    val second = data.copyOfRange(splitIndex, data.size)
    return reshapeData(first) + reshapeData(second)
}

private val secureRandom = SecureRandom()

/**
 * Adds Vision padding. Frame format:
 * `[UUID 16 (first packet only)] [command 1] [contentLen 2] [paddingLen 2] [content] [padding]`
 */
fun visionPadding(data: ByteArray?, command: VisionCommand, state: VisionTrafficState, longPadding: Boolean): ByteArray {
    val contentLen = data?.size ?: 0
    var paddingLen: Int

    // testseed = [contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]
    val seed = state.testseed
    if (contentLen < seed[0] && longPadding) {
        paddingLen = secureRandom.nextInt(seed[1]) + seed[2] - contentLen
    } else {
        paddingLen = secureRandom.nextInt(seed[3])
    }

    val maxPadding = 8192 - 21 - contentLen
    paddingLen = min(paddingLen, maxPadding)
    paddingLen = max(paddingLen, 0)

    val uuidPart = state.writeOnceUserUUID
    val uuidLen = uuidPart?.size ?: 0
    if (uuidPart != null) {
        state.writeOnceUserUUID = null
    }

    val result = ByteArray(uuidLen + 5 + contentLen + paddingLen)
    var offset = 0

    if (uuidPart != null) {
        System.arraycopy(uuidPart, 0, result, offset, uuidPart.size)
        offset += uuidPart.size
    }

    result[offset++] = command.value
    result[offset++] = (contentLen shr 8).toByte()
    result[offset++] = (contentLen and 0xFF).toByte()
    result[offset++] = (paddingLen shr 8).toByte()
    result[offset++] = (paddingLen and 0xFF).toByte()

    if (data != null) {
        System.arraycopy(data, 0, result, offset, data.size)
        offset += data.size
    }

    if (paddingLen > 0) {
        val padding = ByteArray(paddingLen)
        secureRandom.nextBytes(padding)
        System.arraycopy(padding, 0, result, offset, paddingLen)
    }

    return result
}

/** Removes Vision padding from [data] and returns the extracted content. */
fun visionUnpadding(data: DataCursor, state: VisionTrafficState): ByteArray {
    if (state.remainingCommand == -1 && state.remainingContent == -1 && state.remainingPadding == -1) {
        if (data.remaining >= 21 && data.startsWith(state.userUUID)) {
            data.advance(16)
            state.remainingCommand = 5
        } else {
            return data.readAll()
        }
    }

    val result = ByteArrayOutputStream(max(data.remaining, 64))

    while (data.remaining > 0) {
        if (state.remainingCommand > 0) {
            val byte = data.readByte()
            when (state.remainingCommand) {
                5 -> state.currentCommand = byte.toInt() and 0xFF
                4 -> state.remainingContent = (byte.toInt() and 0xFF) shl 8
                3 -> state.remainingContent = state.remainingContent or (byte.toInt() and 0xFF)
                2 -> state.remainingPadding = (byte.toInt() and 0xFF) shl 8
                1 -> state.remainingPadding = state.remainingPadding or (byte.toInt() and 0xFF)
            }
            state.remainingCommand--
        } else if (state.remainingContent > 0) {
            val toRead = min(state.remainingContent, data.remaining)
            val chunk = data.readBytes(toRead)
            result.write(chunk, 0, chunk.size)
            state.remainingContent -= toRead
        } else if (state.remainingPadding > 0) {
            val toSkip = min(state.remainingPadding, data.remaining)
            data.advance(toSkip)
            state.remainingPadding -= toSkip
        }

        if (state.remainingCommand <= 0 && state.remainingContent <= 0 && state.remainingPadding <= 0) {
            if (state.currentCommand == 0) {
                state.remainingCommand = 5
            } else {
                state.remainingCommand = -1
                state.remainingContent = -1
                state.remainingPadding = -1
                if (data.remaining > 0) {
                    val rest = data.readAll()
                    result.write(rest, 0, rest.size)
                }
                break
            }
        }
    }

    return result.toByteArray()
}

class DataCursor(private val data: ByteArray, private var offset: Int = 0) {
    val remaining: Int get() = data.size - offset

    fun startsWith(prefix: ByteArray): Boolean {
        if (remaining < prefix.size) return false
        for (i in prefix.indices) {
            if (data[offset + i] != prefix[i]) return false
        }
        return true
    }

    fun advance(count: Int) {
        offset += count
    }

    fun readByte(): Byte = data[offset++]

    fun readBytes(count: Int): ByteArray {
        val result = data.copyOfRange(offset, offset + count)
        offset += count
        return result
    }

    fun readAll(): ByteArray {
        val result = data.copyOfRange(offset, data.size)
        offset = data.size
        return result
    }
}

/** Detects TLS 1.3 server responses and decides whether to enable XTLS direct copy. */
fun visionFilterTLS(data: ByteArray, state: VisionTrafficState) {
    if (state.numberOfPacketsToFilter <= 0) return
    state.numberOfPacketsToFilter--

    if (data.size < 6) return

    val byte0 = data[0]
    val byte1 = data[1]
    val byte2 = data[2]
    val byte5 = data[5]

    if (byte0 == 0x16.toByte() && byte1 == 0x03.toByte() && byte2 == 0x03.toByte() &&
        byte5 == TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
        val byte3 = data[3]
        val byte4 = data[4]
        state.remainingServerHello = ((byte3.toInt() and 0xFF) shl 8 or (byte4.toInt() and 0xFF)) + 5
        state.isTLS12orAbove = true
        state.isTLS = true

        if (data.size >= 79 && state.remainingServerHello >= 79) {
            val sessionIdLen = data[43].toInt() and 0xFF
            val cipherOffset = 43 + sessionIdLen + 1
            if (data.size > cipherOffset + 2) {
                state.cipher = (data[cipherOffset].toInt() and 0xFF shl 8) or
                        (data[cipherOffset + 1].toInt() and 0xFF)
            }
        }
    } else if (byte0 == 0x16.toByte() && byte1 == 0x03.toByte() &&
        byte5 == TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        state.isTLS = true
    }

    if (state.remainingServerHello > 0) {
        val end = min(state.remainingServerHello, data.size)
        state.remainingServerHello -= data.size

        if (containsSubarray(data, 0, end, TLS13_SUPPORTED_VERSIONS)) {
            if (state.cipher in TLS13_CIPHER_SUITES) {
                state.enableXtls = true
            }
            state.numberOfPacketsToFilter = 0
            return
        } else if (state.remainingServerHello <= 0) {
            state.numberOfPacketsToFilter = 0
            return
        }
    }
}

/**
 * Returns the end offset of the last complete TLS Application Data (`0x17 0x03 0x03`)
 * record in [data], allowing leading `ChangeCipherSpec` (`0x14`) or `Handshake` (`0x16`)
 * records (e.g. TLS 1.3 Flight 3 `CCS + Finished`). If [data] has trailing bytes after
 * the last complete `0x17` record, those trailing bytes must begin with a valid `0x17 0x03 0x03`
 * header so that splitting at the returned offset leaves the remainder record-aligned.
 * Returns -1 if no complete `0x17` record is found.
 */
internal fun findLastCompleteTlsAppDataEnd(data: ByteArray): Int {
    if (data.size < 6) return -1
    var offset = 0
    var lastAppDataEnd = -1

    while (offset < data.size) {
        if (offset + 5 > data.size) {
            if (lastAppDataEnd > 0) {
                val rem = data.size - offset
                if (rem >= 1 && data[offset] != 0x17.toByte()) return -1
                if (rem >= 2 && data[offset + 1] != 0x03.toByte()) return -1
                if (rem >= 3 && data[offset + 2] != 0x03.toByte()) return -1
            }
            break
        }
        val type = data[offset].toInt() and 0xFF
        val major = data[offset + 1].toInt() and 0xFF
        val minor = data[offset + 2].toInt() and 0xFF
        if (major != 0x03 || minor !in 0x01..0x03) return -1
        if (type != 0x17 && type != 0x14 && type != 0x16) return -1
        if (type == 0x17 && minor != 0x03) return -1

        val recordLen = ((data[offset + 3].toInt() and 0xFF) shl 8) or (data[offset + 4].toInt() and 0xFF)
        if (recordLen <= 0 || recordLen > 18432) return -1

        if (offset + 5 + recordLen > data.size) {
            if (type != 0x17) return -1
            break
        }
        offset += 5 + recordLen
        if (type == 0x17) {
            lastAppDataEnd = offset
        }
    }

    return lastAppDataEnd
}

fun isCompleteTlsRecord(data: ByteArray): Boolean {
    return findLastCompleteTlsAppDataEnd(data) == data.size
}

private fun containsSubarray(data: ByteArray, fromIndex: Int, toIndex: Int, sub: ByteArray): Boolean {
    if (sub.isEmpty()) return true
    val end = min(toIndex, data.size) - sub.size
    outer@ for (i in fromIndex..end) {
        for (j in sub.indices) {
            if (data[i + j] != sub[j]) continue@outer
        }
        return true
    }
    return false
}

/**
 * VLESS connection wrapper with Vision flow control.
 */
class VlessVisionConnection(
    private val innerConnection: VlessConnection,
    userUUID: ByteArray,
    testseed: IntArray = intArrayOf(900, 500, 900, 256)
) : VlessConnection() {

    private val trafficState = VisionTrafficState(userUUID, testseed)
    private val lock = Any()

    /**
     * Sends the VLESS request [header] and the first padded frame as one write.
     *
     * Xray composes them through one buffered writer, and for a reason: a
     * header in a TLS record of its own has a length an observer can read off
     * the wire, and hiding that length is exactly what the padding is for.
     * With no [initialData] the frame is pure long padding, as Xray inserts
     * when the app has nothing to say within its wait. Synchronous on purpose:
     * an async write could let the caller's next frame overtake the one that
     * carries the UUID.
     */
    suspend fun sendRequest(header: ByteArray, initialData: ByteArray?) {
        val frame: ByteArray
        val remainder: ByteArray?
        val remainderDirect: Boolean
        synchronized(lock) {
            if (initialData == null || initialData.isEmpty()) {
                frame = visionPadding(null, VisionCommand.PADDING_CONTINUE, trafficState, true)
                remainder = null
                remainderDirect = false
            } else {
                val splitEnd = if (trafficState.writerIsPadding && trafficState.isTLS) {
                    findLastCompleteTlsAppDataEnd(initialData)
                } else -1
                if (splitEnd in 1 until initialData.size) {
                    frame = processSendData(initialData.copyOfRange(0, splitEnd))
                    remainder = initialData.copyOfRange(splitEnd, initialData.size)
                    remainderDirect = trafficState.writerDirectCopy
                } else {
                    frame = processSendData(initialData)
                    remainder = null
                    remainderDirect = false
                }
            }
        }
        innerConnection.send(header + frame)
        if (remainder != null) {
            if (remainderDirect) {
                innerConnection.sendDirectRaw(remainder)
            } else {
                innerConnection.send(remainder)
            }
        }
    }

    override val isConnected: Boolean get() = innerConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        val isDirectCopy: Boolean
        val paddedData: ByteArray
        val remainder: ByteArray?
        val remainderDirect: Boolean
        synchronized(lock) {
            isDirectCopy = trafficState.writerDirectCopy
            if (!isDirectCopy && trafficState.writerIsPadding) {
                if (trafficState.numberOfPacketsToFilter > 0) {
                    visionFilterTLS(data, trafficState)
                }
                val splitEnd = if (trafficState.isTLS) findLastCompleteTlsAppDataEnd(data) else -1
                if (splitEnd in 1 until data.size) {
                    paddedData = processSendDataFiltered(data.copyOfRange(0, splitEnd))
                    remainder = data.copyOfRange(splitEnd, data.size)
                    remainderDirect = trafficState.writerDirectCopy
                } else {
                    paddedData = processSendDataFiltered(data)
                    remainder = null
                    remainderDirect = false
                }
            } else {
                paddedData = processSendData(data)
                remainder = null
                remainderDirect = false
            }
        }

        if (isDirectCopy) {
            innerConnection.sendDirectRaw(paddedData)
        } else {
            innerConnection.send(paddedData)
            if (remainder != null) {
                if (remainderDirect) {
                    innerConnection.sendDirectRaw(remainder)
                } else {
                    innerConnection.send(remainder)
                }
            }
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        val isDirectCopy: Boolean
        val paddedData: ByteArray
        val remainder: ByteArray?
        val remainderDirect: Boolean
        synchronized(lock) {
            isDirectCopy = trafficState.writerDirectCopy
            if (!isDirectCopy && trafficState.writerIsPadding) {
                if (trafficState.numberOfPacketsToFilter > 0) {
                    visionFilterTLS(data, trafficState)
                }
                val splitEnd = if (trafficState.isTLS) findLastCompleteTlsAppDataEnd(data) else -1
                if (splitEnd in 1 until data.size) {
                    paddedData = processSendDataFiltered(data.copyOfRange(0, splitEnd))
                    remainder = data.copyOfRange(splitEnd, data.size)
                    remainderDirect = trafficState.writerDirectCopy
                } else {
                    paddedData = processSendDataFiltered(data)
                    remainder = null
                    remainderDirect = false
                }
            } else {
                paddedData = processSendData(data)
                remainder = null
                remainderDirect = false
            }
        }

        if (isDirectCopy) {
            innerConnection.sendDirectRawAsync(paddedData)
        } else {
            innerConnection.sendAsync(paddedData)
            if (remainder != null) {
                if (remainderDirect) {
                    innerConnection.sendDirectRawAsync(remainder)
                } else {
                    innerConnection.sendAsync(remainder)
                }
            }
        }
    }

    private fun processSendData(data: ByteArray): ByteArray {
        // Outbound bytes go through the same filter as inbound ones, as in
        // Xray's VisionWriter: it is what notices the ClientHello (so the
        // padding becomes long), and each write it inspects counts against the
        // same packet budget the reader draws on.
        if (trafficState.numberOfPacketsToFilter > 0) {
            visionFilterTLS(data, trafficState)
        }
        return processSendDataFiltered(data)
    }

    private fun processSendDataFiltered(data: ByteArray): ByteArray {
        if (trafficState.writerDirectCopy) return data
        if (!trafficState.writerIsPadding) return data

        val longPadding = trafficState.isTLS
        val isComplete = isCompleteTlsRecord(data)

        val chunks = reshapeData(data)
        val out = ByteArrayOutputStream(data.size + chunks.size * 64)

        if (trafficState.isTLS && data.size >= 6 && isComplete) {
            for ((i, chunk) in chunks.withIndex()) {
                val frame = if (i == chunks.size - 1) {
                    val command: VisionCommand
                    if (trafficState.enableXtls) {
                        command = VisionCommand.PADDING_DIRECT
                        trafficState.writerDirectCopy = true
                    } else {
                        command = VisionCommand.PADDING_END
                    }
                    trafficState.writerIsPadding = false
                    visionPadding(chunk, command, trafficState, false)
                } else {
                    visionPadding(chunk, VisionCommand.PADDING_CONTINUE, trafficState, true)
                }
                out.write(frame)
            }
            return out.toByteArray()
        }

        // End padding once the filter budget expires (or one packet early for
        // pre-TLS1.2 receivers) so segmented uploads never stay trapped in
        // PADDING_CONTINUE for the life of the connection.
        if ((!trafficState.isTLS12orAbove && trafficState.numberOfPacketsToFilter <= 1) ||
            trafficState.numberOfPacketsToFilter <= 0) {
            trafficState.writerIsPadding = false
            for ((i, chunk) in chunks.withIndex()) {
                val cmd = if (i == chunks.size - 1) VisionCommand.PADDING_END else VisionCommand.PADDING_CONTINUE
                val frame = visionPadding(chunk, cmd, trafficState, longPadding)
                out.write(frame)
            }
            return out.toByteArray()
        }

        for (chunk in chunks) {
            val frame = visionPadding(chunk, VisionCommand.PADDING_CONTINUE, trafficState, longPadding)
            out.write(frame)
        }
        return out.toByteArray()
    }

    override suspend fun receiveRaw(): ByteArray? {
        return receiveRawInternal()
    }

    private suspend fun receiveRawInternal(): ByteArray? {
        val isDirectCopy: Boolean
        synchronized(lock) {
            isDirectCopy = trafficState.readerDirectCopy
        }

        if (isDirectCopy) {
            return innerConnection.receiveDirectRaw()
        } else {
            val data: ByteArray?
            try {
                data = innerConnection.receive()
            } catch (e: RealityError.DecryptionFailed) {
                // Reality decrypt failure signals the server has transitioned to direct
                // copy mode (sending raw inner TLS without Reality encryption). Switch
                // the reader to direct copy and surface the raw data.
                synchronized(lock) {
                    trafficState.readerDirectCopy = true
                    trafficState.readerWithinPaddingBuffers = false
                }
                val rawData = e.rawData
                if (rawData != null && rawData.isNotEmpty()) {
                    return rawData
                }
                return innerConnection.receiveDirectRaw()
            }

            if (data == null || data.isEmpty()) return null

            val processedData: ByteArray
            synchronized(lock) {
                processedData = processReceiveData(data)
            }

            // Empty after processing means only padding was received; recurse rather
            // than returning null (which would close the connection).
            return if (processedData.isEmpty()) {
                receiveRawInternal()
            } else {
                processedData
            }
        }
    }

    // Skip response-header processing here — the inner connection handles it.
    override suspend fun receive(): ByteArray? = receiveRaw()

    private fun processReceiveData(data: ByteArray): ByteArray {
        if (trafficState.readerDirectCopy) return data

        var content = data
        if (trafficState.readerWithinPaddingBuffers || trafficState.numberOfPacketsToFilter > 0) {
            val cursor = DataCursor(data)
            content = visionUnpadding(cursor, trafficState)

            if (trafficState.remainingContent > 0 || trafficState.remainingPadding > 0 || trafficState.currentCommand == 0) {
                trafficState.readerWithinPaddingBuffers = true
            } else if (trafficState.currentCommand == 1) {
                trafficState.readerWithinPaddingBuffers = false
            } else if (trafficState.currentCommand == 2) {
                trafficState.readerWithinPaddingBuffers = false
                trafficState.readerDirectCopy = true
            }
        }

        // The filter looks for the ServerHello, which only exists once the
        // padding is off: run on the padded bytes (which begin with the UUID)
        // it never matched, TLS 1.3 was never detected, and the uplink stayed
        // double-encrypted for the life of the connection. Xray's VisionReader
        // unpads first for the same reason, and like it skips an empty result
        // (pure padding) so it does not spend a packet of the budget.
        if (content.isNotEmpty() && trafficState.numberOfPacketsToFilter > 0) {
            visionFilterTLS(content, trafficState)
        }

        return content
    }

    override fun cancel() {
        innerConnection.cancel()
    }
}
