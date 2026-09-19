package com.mythaia.vpn.util


fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToByteArray(): ByteArray {
    val hex = replace(" ", "")
    require(hex.length % 2 == 0) { "Hex string must have even length" }
    return ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

fun String.hexToByteArrayOrNull(): ByteArray? = runCatching { hexToByteArray() }.getOrNull()

fun ByteArray.toBase64Url(): String =
    java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(this)

fun String.base64UrlToByteArray(): ByteArray =
    java.util.Base64.getUrlDecoder().decode(this.trim())

/**
 * Decodes the way Android's lenient decoder did: whitespace and line breaks
 * are skipped and the trailing padding is optional. [urlSafe] selects the
 * `-_` alphabet; the standard `+/` alphabet otherwise.
 */
fun decodeBase64Lenient(text: String, urlSafe: Boolean = false): ByteArray {
    val cleaned = text.filterNot { it.isWhitespace() }
    val decoder = if (urlSafe) java.util.Base64.getUrlDecoder() else java.util.Base64.getDecoder()
    return decoder.decode(cleaned)
}

fun String.base64UrlToByteArrayOrNull(): ByteArray? =
    runCatching { base64UrlToByteArray() }.getOrNull()
