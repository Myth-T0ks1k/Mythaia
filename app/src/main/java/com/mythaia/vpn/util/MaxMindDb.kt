package com.mythaia.vpn.util

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

private val logger = MythaiaLogger("GeoIP")

/**
 * A reader for the MaxMind DB format (`.mmdb`), enough of it to answer one
 * question: which country is this address in.
 *
 * The file is a binary search tree over the bits of the address, followed by a
 * section of records the leaves point into. Only the fields a country lookup
 * needs are decoded; the rest of the record is walked past rather than built
 * into objects, so a lookup allocates almost nothing.
 *
 * Memory-mapped, so a 6 MB database costs address space rather than heap, and
 * the pages the lookups touch stay resident while the rest never loads.
 */
class MaxMindDb private constructor(
    private val buffer: ByteBuffer,
    private val nodeCount: Int,
    private val recordSize: Int,
    private val ipVersion: Int,
    private val searchTreeSize: Int
) {

    /** Where the record section begins, past the 16-byte separator. */
    private val dataSectionStart = searchTreeSize + DATA_SEPARATOR_SIZE

    /**
     * The ISO country code for [address], uppercase, or null when the database
     * has no answer.
     *
     * @param address 4 bytes for IPv4, 16 for IPv6.
     */
    fun countryCode(address: ByteArray): String? = when {
        address.size == 16 -> {
            // A v6 address has no answer in a v4-only tree. Walking it anyway
            // would follow its first four bytes and return whichever IPv4
            // address happens to share them.
            if (ipVersion == 4) null else lookup(address, startNode = 0)
        }
        // In a v6 tree the IPv4 data lives under ::/96, which is where the
        // 32-bit walk has to begin. Some databases also alias ::ffff:0:0/96,
        // but not all do, so the subtree is found rather than assumed.
        address.size == 4 -> lookup(address, startNode = if (ipVersion == 6) ipv4StartNode else 0)
        else -> null
    }

    /** The country at [address], starting the walk at [startNode]. */
    private fun lookup(address: ByteArray, startNode: Int): String? {
        // Anything malformed in the file surfaces here rather than escaping to
        // the caller, which on the routing path is a JNI upcall.
        if (startNode < 0) return null
        return runCatching { findRecord(address, startNode)?.let(::decodeCountry) }.getOrNull()
    }

    /** Walks the search tree; returns an offset into the data section. */
    private fun findRecord(address: ByteArray, startNode: Int): Int? {
        var node = startNode
        val bitCount = address.size * 8

        for (i in 0 until bitCount) {
            if (node >= nodeCount) break
            val bit = (address[i / 8].toInt() shr (7 - (i % 8))) and 1
            node = readNode(node, bit)
        }

        return when {
            // nodeCount means "no data here" — the tree's own null.
            node == nodeCount -> null
            node > nodeCount -> node - nodeCount + searchTreeSize
            else -> null
        }
    }

    /**
     * The node the IPv4 subtree of a v6 tree hangs off: 96 zero bits down from
     * the root.
     *
     * Computed once. -1 when the database has no IPv4 subtree at all, which
     * [lookup] reads as "no answer" rather than walking from a bogus node.
     */
    private val ipv4StartNode: Int by lazy {
        if (ipVersion != 6) return@lazy 0
        var node = 0
        repeat(96) {
            if (node >= nodeCount) return@lazy -1
            node = readNode(node, 0)
        }
        if (node >= nodeCount) -1 else node
    }

    /** One half of a tree node, at [recordSize] bits per half. */
    private fun readNode(node: Int, side: Int): Int {
        val base = node * recordSize * 2 / 8
        return when (recordSize) {
            24 -> {
                val at = base + side * 3
                (u8(at) shl 16) or (u8(at + 1) shl 8) or u8(at + 2)
            }
            28 -> {
                // The middle byte carries the top nibble of both halves: the
                // high nibble belongs to the left record, the low to the right.
                val middle = u8(base + 3)
                if (side == 0) {
                    ((middle and 0xF0) shl 20) or (u8(base) shl 16) or
                        (u8(base + 1) shl 8) or u8(base + 2)
                } else {
                    ((middle and 0x0F) shl 24) or (u8(base + 4) shl 16) or
                        (u8(base + 5) shl 8) or u8(base + 6)
                }
            }
            32 -> {
                val at = base + side * 4
                (u8(at) shl 24) or (u8(at + 1) shl 16) or (u8(at + 2) shl 8) or u8(at + 3)
            }
            else -> throw IllegalStateException("unsupported record size $recordSize")
        }
    }

    /**
     * Reads `country.iso_code` (or `registered_country.iso_code`) out of the
     * record at [offset].
     */
    private fun decodeCountry(offset: Int): String? {
        val country = lookupMapKey(offset, "country")
            ?: lookupMapKey(offset, "registered_country")
            ?: return null
        return lookupMapKey(country, "iso_code")?.let { readString(it) }?.uppercase()
    }

    /** The offset of [key]'s value inside the map at [offset], or null. */
    private fun lookupMapKey(offset: Int, key: String): Int? {
        val (type, size, after) = readControl(offset)
        if (type != TYPE_MAP) return null

        var at = after
        repeat(size) {
            val keyOffset = resolvePointer(at)
            val keyText = readString(keyOffset.target) ?: return null
            at = keyOffset.next
            val valueStart = at
            if (keyText == key) {
                // A value may itself be a pointer to somewhere else in the
                // section; callers want where the value actually lives.
                return resolvePointer(valueStart).target
            }
            at = skipValue(valueStart)
        }
        return null
    }

    private class Resolved(val target: Int, val next: Int)

    /**
     * Follows a pointer if [offset] holds one.
     *
     * `target` is where the value lives, `next` is where the field after this
     * one starts — which for a pointer is just past the pointer itself.
     */
    private fun resolvePointer(offset: Int): Resolved {
        val control = u8(offset)
        val type = control shr 5
        if (type != TYPE_POINTER) return Resolved(offset, skipValue(offset))

        val size = (control shr 3) and 0x03
        val low = control and 0x07
        return when (size) {
            0 -> Resolved(dataSectionStart + ((low shl 8) or u8(offset + 1)), offset + 2)
            1 -> Resolved(
                dataSectionStart + 2048 +
                    ((low shl 16) or (u8(offset + 1) shl 8) or u8(offset + 2)),
                offset + 3
            )
            2 -> Resolved(
                dataSectionStart + 526336 +
                    ((low shl 24) or (u8(offset + 1) shl 16) or
                        (u8(offset + 2) shl 8) or u8(offset + 3)),
                offset + 4
            )
            else -> Resolved(
                dataSectionStart +
                    ((u8(offset + 1) shl 24) or (u8(offset + 2) shl 16) or
                        (u8(offset + 3) shl 8) or u8(offset + 4)),
                offset + 5
            )
        }
    }

    /** Type, payload size, and where the payload starts. */
    private fun readControl(offset: Int): Triple<Int, Int, Int> {
        val control = u8(offset)
        var type = control shr 5
        var at = offset + 1

        if (type == TYPE_EXTENDED) {
            type = u8(at) + 7
            at += 1
        }

        var size = control and 0x1F
        when (size) {
            29 -> { size = 29 + u8(at); at += 1 }
            30 -> { size = 285 + ((u8(at) shl 8) or u8(at + 1)); at += 2 }
            31 -> {
                size = 65821 + ((u8(at) shl 16) or (u8(at + 1) shl 8) or u8(at + 2))
                at += 3
            }
        }
        return Triple(type, size, at)
    }

    /** The offset just past the value at [offset]. */
    private fun skipValue(offset: Int): Int {
        val control = u8(offset)
        if (control shr 5 == TYPE_POINTER) {
            return when ((control shr 3) and 0x03) {
                0 -> offset + 2
                1 -> offset + 3
                2 -> offset + 4
                else -> offset + 5
            }
        }

        val (type, size, after) = readControl(offset)
        return when (type) {
            TYPE_MAP -> {
                var at = after
                repeat(size) {
                    at = skipValue(at)     // key
                    at = skipValue(at)     // value
                }
                at
            }
            TYPE_ARRAY -> {
                var at = after
                repeat(size) { at = skipValue(at) }
                at
            }
            // Booleans carry their value in the size field and occupy no payload.
            TYPE_BOOLEAN -> after
            else -> after + size
        }
    }

    private fun readString(offset: Int): String? {
        val (type, size, after) = readControl(offset)
        if (type != TYPE_STRING) return null
        val bytes = ByteArray(size)
        for (i in 0 until size) bytes[i] = buffer.get(after + i)
        return String(bytes, Charsets.UTF_8)
    }

    private fun u8(at: Int): Int = buffer.get(at).toInt() and 0xFF

    companion object {
        private const val DATA_SEPARATOR_SIZE = 16

        private const val TYPE_EXTENDED = 0
        private const val TYPE_POINTER = 1
        private const val TYPE_STRING = 2
        private const val TYPE_MAP = 7
        private const val TYPE_ARRAY = 11
        private const val TYPE_BOOLEAN = 14

        /**
         * The literal bytes `AB CD EF` followed by "MaxMind.com".
         *
         * Spelled out rather than written as text: the first three are not
         * printable characters, and any encoding step on the way in would
         * change them.
         */
        private val METADATA_MARKER =
            byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()) +
                "MaxMind.com".toByteArray(Charsets.US_ASCII)

        /** Opens [file], or returns null when it is not a usable database. */
        fun open(file: File): MaxMindDb? = try {
            RandomAccessFile(file, "r").use { raf ->
                val buffer = raf.channel.map(FileChannel.MapMode.READ_ONLY, 0, raf.length())
                parse(buffer)
            }
        } catch (e: Exception) {
            logger.warning("[GeoIP] Cannot open ${file.name}: ${e.message ?: e}")
            null
        }

        private fun parse(buffer: ByteBuffer): MaxMindDb? {
            val metadataStart = findMetadata(buffer) ?: run {
                logger.warning("[GeoIP] No MaxMind metadata marker")
                return null
            }

            // Bootstrap: the metadata is itself a record, so it is read by a
            // reader whose data section starts where the metadata does.
            val bootstrap = MaxMindDb(
                buffer = buffer,
                nodeCount = 0,
                recordSize = 24,
                ipVersion = 6,
                searchTreeSize = metadataStart - DATA_SEPARATOR_SIZE
            )

            val nodeCount = bootstrap.readUnsigned(metadataStart, "node_count") ?: return null
            val recordSize = bootstrap.readUnsigned(metadataStart, "record_size") ?: return null
            val ipVersion = bootstrap.readUnsigned(metadataStart, "ip_version") ?: 6

            if (recordSize != 24 && recordSize != 28 && recordSize != 32) {
                logger.warning("[GeoIP] Unsupported record size $recordSize")
                return null
            }

            // The tree size is derived from header fields, so a corrupt or
            // hostile file could put it past the end of the mapping and every
            // node read would then be out of bounds. Computed wide to catch the
            // overflow, and checked against what is actually mapped.
            val treeSize = nodeCount.toLong() * recordSize * 2 / 8
            if (nodeCount <= 0 || treeSize <= 0 ||
                treeSize + DATA_SEPARATOR_SIZE > buffer.limit()
            ) {
                logger.warning("[GeoIP] Header describes a $treeSize-byte tree in a ${buffer.limit()}-byte file")
                return null
            }

            val searchTreeSize = treeSize.toInt()
            logger.debug("[GeoIP] Opened database: $nodeCount nodes, ${recordSize}-bit records, IPv$ipVersion")

            return MaxMindDb(buffer, nodeCount, recordSize, ipVersion, searchTreeSize)
        }

        /**
         * The metadata sits after the last occurrence of the marker, so the
         * search runs backwards from the end of the file.
         */
        private fun findMetadata(buffer: ByteBuffer): Int? {
            val limit = buffer.limit()
            // The metadata block is capped at 128 KiB by the format.
            val earliest = maxOf(0, limit - 128 * 1024)
            outer@ for (start in limit - METADATA_MARKER.size downTo earliest) {
                for (i in METADATA_MARKER.indices) {
                    if (buffer.get(start + i) != METADATA_MARKER[i]) continue@outer
                }
                return start + METADATA_MARKER.size
            }
            return null
        }
    }

    /** An unsigned integer field of the metadata map. */
    private fun readUnsigned(mapOffset: Int, key: String): Int? {
        val at = lookupMapKey(mapOffset, key) ?: return null
        val (_, size, after) = readControl(at)
        var value = 0
        for (i in 0 until size) value = (value shl 8) or u8(after + i)
        return value
    }
}
