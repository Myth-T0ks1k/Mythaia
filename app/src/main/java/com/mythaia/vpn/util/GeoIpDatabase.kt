package com.mythaia.vpn.util

import android.content.Context
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

private val logger = MythaiaLogger("GeoIP")

/**
 * The user-supplied GeoIP database, and the country lookups routing does
 * against it.
 *
 * No database ships with the app: GeoLite2 is several megabytes and carries
 * MaxMind's own licence and attribution terms, so the user brings their own
 * `.mmdb`. With none imported, every `geoip:` rule simply does not match and
 * routing falls through to the rules around it.
 */
object GeoIpDatabase {

    private const val FILE_NAME = "geoip.mmdb"

    @Volatile
    private var database: MaxMindDb? = null

    /** Answers are stable for the life of a database, and lookups repeat a lot. */
    private val cache = ConcurrentHashMap<String, String>()

    /** Marks an address the database has no answer for, so it is not re-walked. */
    private const val NO_COUNTRY = "??"

    private const val MAX_CACHE = 4096

    val isLoaded: Boolean
        get() = database != null

    fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    /** Opens the imported database, if there is one. Safe to call repeatedly. */
    fun load(context: Context) {
        val file = file(context)
        if (!file.exists()) {
            database = null
            cache.clear()
            return
        }
        val opened = MaxMindDb.open(file)
        database = opened
        cache.clear()
        if (opened == null) {
            logger.warning("[GeoIP] ${file.name} is not a usable database")
        }
    }

    /**
     * Replaces the database with the bytes from [input].
     *
     * Written to a temporary file and moved into place, so an interrupted
     * import cannot leave a half-written database that fails to open on the
     * next start.
     *
     * @return true when the new file opened successfully.
     */
    fun import(context: Context, input: InputStream): Boolean {
        val target = file(context)
        val temp = File(context.filesDir, "$FILE_NAME.tmp")
        return try {
            temp.outputStream().use { output -> input.copyTo(output) }

            if (MaxMindDb.open(temp) == null) {
                temp.delete()
                logger.warning("[GeoIP] Imported file is not a MaxMind database")
                return false
            }

            if (target.exists()) target.delete()
            val moved = temp.renameTo(target)
            if (!moved) {
                temp.delete()
                logger.warning("[GeoIP] Could not move the imported database into place")
                return false
            }

            load(context)
            isLoaded
        } catch (e: Exception) {
            runCatching { temp.delete() }
            logger.warning("[GeoIP] Import failed: ${e.message ?: e}")
            false
        }
    }

    /** Removes the imported database. */
    fun clear(context: Context) {
        file(context).delete()
        database = null
        cache.clear()
    }

    /**
     * The ISO country code for [ip], uppercase, or null when there is no
     * database or it has no answer.
     */
    fun countryCode(ip: String): String? {
        val db = database ?: return null

        cache[ip]?.let { return if (it == NO_COUNTRY) null else it }

        val address = try {
            // Parses a literal without ever resolving: a hostname here would
            // mean a DNS lookup on the routing path.
            if (!DnsCache.isIpAddress(ip)) return null
            InetAddress.getByName(ip).address
        } catch (_: Exception) {
            return null
        }

        val code = db.countryCode(address)

        // A bounded cache: routing sees a long tail of addresses, and an
        // unbounded map would grow with the session.
        if (cache.size >= MAX_CACHE) cache.clear()
        cache[ip] = code ?: NO_COUNTRY

        return code
    }

    /** Whether [ip] is in [countryCode], which is compared case-insensitively. */
    fun matches(ip: String, countryCode: String): Boolean =
        countryCode(ip)?.equals(countryCode, ignoreCase = true) == true
}
