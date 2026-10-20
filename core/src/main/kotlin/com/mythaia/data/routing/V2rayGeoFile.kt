package com.mythaia.data.routing

import java.io.BufferedInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream

/**
 * Readers for the two rule files v2fly and Xray clients download:
 * `geosite.dat`, domain lists by category, and `geoip.dat`, address ranges
 * by country or service.
 *
 * Each file is one protobuf message holding a list of entries, and a profile
 * names only a handful of them. So the file is streamed, each entry's name is
 * read first, and an entry nobody asked for is skipped by its length without
 * being decoded: picking `geosite:category-ru` out of an eight-megabyte file
 * reads the names of the others and nothing more.
 *
 * ```
 * GeoSiteList { repeated GeoSite entry = 1; }
 * GeoSite     { string country_code = 1; repeated Domain domain = 2; }
 * Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
 * Attribute   { string key = 1; bool bool_value = 2; int64 int_value = 3; }
 * GeoIPList   { repeated GeoIP entry = 1; }
 * GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; string code = 5; }
 * CIDR        { bytes ip = 1; uint32 prefix = 2; }
 * ```
 */
object V2rayGeoFile {

    /** How a geosite domain matches; the numbers are the file's. */
    enum class DomainType {
        /** Anywhere in the name (`keyword:`). */
        PLAIN,
        REGEX,
        /** The name and every name under it (`domain:`). */
        ROOT_DOMAIN,
        /** Exactly the name (`full:`). */
        FULL
    }

    data class Domain(val type: DomainType, val value: String, val attributes: Set<String> = emptySet())

    class Cidr(val ip: ByteArray, val prefix: Int)

    /** One geoip entry; [inverse] matches every address *outside* [cidrs]. */
    class IpList(val cidrs: List<Cidr>, val inverse: Boolean)

    /** Larger than any real list; a bigger length is a corrupt or hostile file. */
    private const val MAX_ENTRY_BYTES = 64 * 1024 * 1024
    private const val MAX_ITEMS_PER_ENTRY = 1_000_000

    /**
     * The domain lists of [codes] (compared case-insensitively) found in
     * [input]. A code the file does not have is simply absent from the map.
     */
    fun readSites(input: InputStream, codes: Set<String>): Map<String, List<Domain>> {
        val wanted = codes.map { it.uppercase() }.toSet()
        val out = HashMap<String, List<Domain>>()
        if (wanted.isEmpty()) return out
        forEachEntry(input, wanted) { code, body ->
            if (code in wanted && code !in out) out[code] = parseSite(body)
            out.size == wanted.size
        }
        return out
    }

    /** The address lists of [codes] found in [input]; see [readSites]. */
    fun readIps(input: InputStream, codes: Set<String>): Map<String, IpList> {
        val wanted = codes.map { it.uppercase() }.toSet()
        val out = HashMap<String, IpList>()
        if (wanted.isEmpty()) return out
        forEachEntry(input, wanted) { code, body ->
            if (code in wanted && code !in out) out[code] = parseIp(body)
            out.size == wanted.size
        }
        return out
    }

    /** Every entry name in [input], in file order: for checking a file and for tests. */
    fun readCodes(input: InputStream): List<String> {
        val out = ArrayList<String>()
        forEachEntry(input, wanted = null) { code, _ -> out += code; false }
        return out
    }

    private val EMPTY_BUFFER = Buffer(ByteArray(0))

    /**
     * Whether [input] is a complete geosite/geoip file: starts with entry 1
     * (length-delimited), every entry has a valid name and runs cleanly to
     * EOF. An HTML error page or a truncated download fails this.
     */
    fun looksValid(input: InputStream): Boolean = try {
        val buffered = if (input is BufferedInputStream) input else BufferedInputStream(input, 64 * 1024)
        buffered.mark(16)
        val first = buffered.read()
        buffered.reset()
        if (first != (1 shl 3 or WIRE_LENGTH)) false
        else {
            var any = false
            forEachEntry(buffered, wanted = null) { code, _ ->
                if (code.isNotEmpty()) any = true
                false
            }
            any
        }
    } catch (_: IOException) {
        false
    }

    /**
     * Walks the top-level entries. [visit] gets each entry's name (upper-case)
     * and its encoded body when the name is in [wanted] (or for every entry
     * when [wanted] is null, then with an empty body), and returns true to stop.
     */
    private fun forEachEntry(input: InputStream, wanted: Set<String>?, visit: (String, Buffer) -> Boolean) {
        val reader = StreamReader(if (input is BufferedInputStream) input else BufferedInputStream(input, 64 * 1024))
        while (true) {
            val tag = reader.readTagOrEnd()
            if (tag < 0) return
            if (tag ushr 3 != 1 || tag and 7 != WIRE_LENGTH) {
                reader.skipField(tag)
                continue
            }
            val length = reader.readVarint()
            if (length < 0 || length > MAX_ENTRY_BYTES) throw IOException("entry of $length bytes")
            if (length == 0L) continue
            val end = reader.position + length
            // The name is the first field in every file the projects publish;
            // when it is not, the entry is read whole and searched.
            val innerTag = reader.readVarint().toInt()
            val code: String
            val stop: Boolean
            if (innerTag == (1 shl 3 or WIRE_LENGTH) || innerTag == (5 shl 3 or WIRE_LENGTH)) {
                val nameLength = reader.readVarint()
                if (nameLength < 0 || reader.position + nameLength > end) throw IOException("bad entry name")
                code = String(reader.readBytes(nameLength.toInt()), Charsets.UTF_8).uppercase()
                if (wanted == null) {
                    reader.skip(end - reader.position)
                    stop = visit(code, EMPTY_BUFFER)
                } else if (code in wanted) {
                    val rest = reader.readBytes((end - reader.position).toInt())
                    stop = visit(code, Buffer(rest))
                } else {
                    reader.skip(end - reader.position)
                    stop = false
                }
            } else {
                // Put the tag back in front of the rest by decoding from a copy.
                val rest = reader.readBytes((end - reader.position).toInt())
                val whole = encodeVarint(innerTag.toLong()) + rest
                code = findName(Buffer(whole)) ?: ""
                stop = when {
                    wanted == null -> visit(code, EMPTY_BUFFER)
                    code in wanted -> visit(code, Buffer(whole))
                    else -> false
                }
            }
            if (stop) return
        }
    }

    private fun findName(entry: Buffer): String? {
        var fallback: String? = null
        while (!entry.atEnd) {
            val tag = entry.readVarint().toInt()
            when {
                tag == (1 shl 3 or WIRE_LENGTH) -> return entry.readString().uppercase()
                tag == (5 shl 3 or WIRE_LENGTH) -> fallback = entry.readString().uppercase()
                else -> entry.skipField(tag)
            }
        }
        return fallback
    }

    private fun parseSite(body: Buffer): List<Domain> {
        val out = ArrayList<Domain>()
        while (!body.atEnd) {
            val tag = body.readVarint().toInt()
            if (tag == (2 shl 3 or WIRE_LENGTH)) {
                val domain = body.readMessage()
                parseDomain(domain)?.let { if (out.size < MAX_ITEMS_PER_ENTRY) out += it }
            } else {
                body.skipField(tag)
            }
        }
        return out
    }

    private fun parseDomain(message: Buffer): Domain? {
        var type = 0
        var value: String? = null
        var attributes: MutableSet<String>? = null
        while (!message.atEnd) {
            val tag = message.readVarint().toInt()
            when (tag) {
                (1 shl 3 or WIRE_VARINT) -> type = message.readVarint().toInt()
                (2 shl 3 or WIRE_LENGTH) -> value = message.readString()
                (3 shl 3 or WIRE_LENGTH) -> {
                    val attribute = message.readMessage()
                    while (!attribute.atEnd) {
                        val attributeTag = attribute.readVarint().toInt()
                        if (attributeTag == (1 shl 3 or WIRE_LENGTH)) {
                            (attributes ?: HashSet<String>().also { attributes = it }) += attribute.readString().lowercase()
                        } else {
                            attribute.skipField(attributeTag)
                        }
                    }
                }
                else -> message.skipField(tag)
            }
        }
        val text = value?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        val kind = DomainType.entries.getOrNull(type) ?: return null
        return Domain(kind, text, attributes ?: emptySet())
    }

    private fun parseIp(body: Buffer): IpList {
        val cidrs = ArrayList<Cidr>()
        var inverse = false
        while (!body.atEnd) {
            val tag = body.readVarint().toInt()
            when (tag) {
                (2 shl 3 or WIRE_LENGTH) -> {
                    val cidr = body.readMessage()
                    var ip: ByteArray? = null
                    var prefix = -1
                    while (!cidr.atEnd) {
                        val cidrTag = cidr.readVarint().toInt()
                        when (cidrTag) {
                            (1 shl 3 or WIRE_LENGTH) -> ip = cidr.readByteArray()
                            (2 shl 3 or WIRE_VARINT) -> prefix = cidr.readVarint().toInt()
                            else -> cidr.skipField(cidrTag)
                        }
                    }
                    val address = ip ?: continue
                    if (address.size != 4 && address.size != 16) continue
                    // proto3 leaves a zero prefix out entirely.
                    val bits = if (prefix < 0) 0 else prefix
                    if (bits > address.size * 8) continue
                    if (cidrs.size < MAX_ITEMS_PER_ENTRY) cidrs += Cidr(address, bits)
                }
                (3 shl 3 or WIRE_VARINT) -> inverse = body.readVarint() != 0L
                else -> body.skipField(tag)
            }
        }
        return IpList(cidrs, inverse)
    }

    private const val WIRE_VARINT = 0
    private const val WIRE_FIXED64 = 1
    private const val WIRE_LENGTH = 2
    private const val WIRE_FIXED32 = 5

    private fun encodeVarint(value: Long): ByteArray {
        val out = ArrayList<Byte>()
        var v = value
        while (true) {
            if (v and 0x7FL.inv() == 0L) {
                out += v.toByte()
                return out.toByteArray()
            }
            out += ((v and 0x7F) or 0x80).toByte()
            v = v ushr 7
        }
    }

    /** A protobuf stream read front to back, skipping what is not wanted. */
    private class StreamReader(private val input: InputStream) {
        var position = 0L
            private set

        private fun readByte(): Int {
            val b = input.read()
            if (b < 0) throw EOFException("unexpected end of file")
            position++
            return b
        }

        /** The next field tag, or -1 at a clean end of the file. */
        fun readTagOrEnd(): Int {
            val first = input.read()
            if (first < 0) return -1
            position++
            if (first and 0x80 == 0) return first
            var result = (first and 0x7F).toLong()
            var shift = 7
            while (true) {
                val b = readByte()
                result = result or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) break
                shift += 7
                if (shift > 35) throw IOException("bad tag")
            }
            return result.toInt()
        }

        fun readVarint(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                val b = readByte()
                result = result or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
                if (shift > 63) throw IOException("bad varint")
            }
        }

        fun readBytes(count: Int): ByteArray {
            if (count < 0 || count > MAX_ENTRY_BYTES) throw IOException("field of $count bytes")
            val out = ByteArray(count)
            var at = 0
            while (at < count) {
                val n = input.read(out, at, count - at)
                if (n < 0) throw EOFException("unexpected end of file")
                at += n
            }
            position += count
            return out
        }

        fun skip(count: Long) {
            var left = count
            while (left > 0) {
                val n = input.skip(left)
                if (n <= 0) {
                    // skip() may refuse to move; one read tells EOF from a pause.
                    if (input.read() < 0) throw EOFException("unexpected end of file")
                    left--
                    position++
                } else {
                    left -= n
                    position += n
                }
            }
        }

        fun skipField(tag: Int) {
            when (tag and 7) {
                WIRE_VARINT -> readVarint()
                WIRE_FIXED64 -> skip(8)
                WIRE_LENGTH -> {
                    val length = readVarint()
                    if (length < 0 || length > MAX_ENTRY_BYTES) throw IOException("field of $length bytes")
                    skip(length)
                }
                WIRE_FIXED32 -> skip(4)
                else -> throw IOException("unsupported wire type ${tag and 7}")
            }
        }
    }

    /** A protobuf message already in memory. */
    private class Buffer(private val bytes: ByteArray, private var at: Int = 0, private val end: Int = bytes.size) {
        val atEnd: Boolean get() = at >= end

        fun readVarint(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                if (at >= end) throw EOFException("truncated message")
                val b = bytes[at++].toInt() and 0xFF
                result = result or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
                if (shift > 63) throw IOException("bad varint")
            }
        }

        private fun length(): Int {
            val length = readVarint()
            if (length < 0 || length > end - at) throw IOException("field runs past its message")
            return length.toInt()
        }

        fun readMessage(): Buffer {
            val length = length()
            val inner = Buffer(bytes, at, at + length)
            at += length
            return inner
        }

        fun readString(): String {
            val length = length()
            val text = String(bytes, at, length, Charsets.UTF_8)
            at += length
            return text
        }

        fun readByteArray(): ByteArray {
            val length = length()
            val out = bytes.copyOfRange(at, at + length)
            at += length
            return out
        }

        fun skipField(tag: Int) {
            when (tag and 7) {
                WIRE_VARINT -> readVarint()
                WIRE_FIXED64 -> advance(8)
                WIRE_LENGTH -> advance(length())
                WIRE_FIXED32 -> advance(4)
                else -> throw IOException("unsupported wire type ${tag and 7}")
            }
        }

        private fun advance(count: Int) {
            if (count > end - at) throw EOFException("truncated message")
            at += count
        }
    }
}
