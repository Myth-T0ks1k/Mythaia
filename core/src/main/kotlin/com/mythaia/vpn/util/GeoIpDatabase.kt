package com.mythaia.vpn.util

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

    const val FILE_NAME = "geoip.mmdb"

    @Volatile
    private var database: MaxMindDb? = null

    /** Answers are stable for the life of a database, and lookups repeat a lot. */
    private val cache = ConcurrentHashMap<String, String>()

    /** Marks an address the database has no answer for, so it is not re-walked. */
    private const val NO_COUNTRY = "??"

    private const val MAX_CACHE = 4096

    val isLoaded: Boolean
        get() = database != null

    /** Opens the imported database at [file], if there is one. Safe to call repeatedly. */
    fun load(file: File) {
        if (!file.exists()) {
            unload()
            return
        }
        val opened = MaxMindDb.open(file)
        val previous = database
        database = opened
        cache.clear()
        previous?.close()
        if (opened == null) {
            logger.warning("[GeoIP] ${file.name} is not a usable database")
        }
    }

    /**
     * Drops the loaded database and releases its file, so the file can be
     * deleted or replaced (which a mapped file cannot be on Windows).
     */
    private fun unload() {
        val previous = database
        database = null
        cache.clear()
        previous?.close()
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
    fun importInto(target: File, input: InputStream): Boolean {
        val temp = File(target.parentFile, "${target.name}.tmp")
        return try {
            temp.outputStream().use { output -> input.copyTo(output) }

            val probe = MaxMindDb.open(temp)
            if (probe == null) {
                temp.delete()
                logger.warning("[GeoIP] Imported file is not a MaxMind database")
                return false
            }
            // The probe's mapping would pin the temp file against the rename
            // the same way the loaded database pins the target.
            probe.close()
            unload()

            if (target.exists() && !target.delete()) {
                temp.delete()
                logger.warning("[GeoIP] Could not replace ${target.name}: the current database is still in use")
                // Put back what was there rather than leave routing without a database.
                load(target)
                return false
            }
            val moved = temp.renameTo(target)
            if (!moved) {
                temp.delete()
                logger.warning("[GeoIP] Could not move the imported database into place")
                return false
            }

            load(target)
            isLoaded
        } catch (e: Exception) {
            runCatching { temp.delete() }
            logger.warning("[GeoIP] Import failed: ${e.message ?: e}")
            false
        }
    }

    /** Removes the imported database. */
    fun clear(file: File) {
        unload()
        if (file.exists() && !file.delete()) {
            logger.warning("[GeoIP] Could not delete ${file.name}; it will be loaded again on the next start")
        }
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
