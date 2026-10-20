package com.mythaia.data.routing

import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress

/** Builds small geosite.dat / geoip.dat files the way v2fly encodes them. */
internal object GeoFixtures {

    private fun varint(value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        while (true) {
            if (v and 0x7FL.inv() == 0L) {
                out.write(v.toInt())
                return out.toByteArray()
            }
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
    }

    private fun tag(field: Int, wire: Int) = varint(((field shl 3) or wire).toLong())
    private fun bytes(field: Int, data: ByteArray) = tag(field, 2) + varint(data.size.toLong()) + data
    private fun string(field: Int, text: String) = bytes(field, text.toByteArray(Charsets.UTF_8))
    private fun number(field: Int, value: Long) = tag(field, 0) + varint(value)

    /** type: 0 plain, 1 regex, 2 domain, 3 full. */
    data class D(val type: Int, val value: String, val attributes: List<String> = emptyList())

    fun site(code: String, vararg domains: D): ByteArray {
        var body = string(1, code)
        for (d in domains) {
            var domain = number(1, d.type.toLong()) + string(2, d.value)
            for (a in d.attributes) domain += bytes(3, string(1, a) + number(2, 1))
            body += bytes(2, domain)
        }
        return body
    }

    fun ip(code: String, vararg cidrs: String, inverse: Boolean = false): ByteArray {
        var body = string(1, code)
        for (c in cidrs) {
            val address = InetAddress.getByName(c.substringBefore('/')).address
            val prefix = c.substringAfter('/').toLong()
            // proto3 drops a zero prefix, as the real files do.
            body += bytes(2, bytes(1, address) + (if (prefix == 0L) ByteArray(0) else number(2, prefix)))
        }
        if (inverse) body += number(3, 1)
        return body
    }

    fun list(vararg entries: ByteArray): ByteArray = entries.fold(ByteArray(0)) { acc, e -> acc + bytes(1, e) }

    fun file(bytes: ByteArray): File = File.createTempFile("geo", ".dat").apply {
        deleteOnExit()
        writeBytes(bytes)
    }

    val sites: ByteArray = list(
        site(
            "CN",
            D(2, "baidu.com"), D(3, "www.qq.com"), D(0, "taobao"),
            D(1, "^cn-[0-9]+\\.example\\.org$"), D(2, "ads-cn.com", listOf("ads"))
        ),
        site("CATEGORY-RU", D(2, "yandex.ru"), D(2, "vk.com")),
        site("ADS", D(2, "doubleclick.net"), D(2, "ads.example.com")),
        site("UNUSED", D(2, "unused.example"))
    )

    val ips: ByteArray = list(
        ip("CN", "1.0.1.0/24", "1.0.2.0/23", "240e::/18"),
        ip("RU", "5.3.0.0/16"),
        ip("TELEGRAM", "91.108.4.0/22", "2001:67c:4e8::/48"),
        ip("PRIVATE", "10.0.0.0/8", "192.168.0.0/16"),
        ip("NOTCN", "1.0.1.0/24", inverse = true)
    )
}
