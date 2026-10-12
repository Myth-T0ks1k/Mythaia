package com.mythaia.desktop.engine

import com.mythaia.data.network.ProtocolProbe
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * The Android protocol matrix on the desktop JVM: every input file named in
 * `MYTHAIA_MATRIX` (separated by ';') is probed through the core and printed
 * as a table. With `MYTHAIA_MATRIX_HOST` set, `10.0.2.2` (the emulator's
 * name for the PC) is rewritten to it, so the emulator's lab file runs here
 * against 127.0.0.1 unchanged.
 */
class LabMatrixSmoke {
    @Test
    fun `every server in the matrix inputs`() = runBlocking {
        val files = System.getenv("MYTHAIA_MATRIX")?.split(';')?.filter { it.isNotBlank() }.orEmpty()
        assumeTrue("MYTHAIA_MATRIX not set", files.isNotEmpty())
        val host = System.getenv("MYTHAIA_MATRIX_HOST")
        if (System.getenv("MYTHAIA_MATRIX_LOG") != null) {
            com.mythaia.vpn.util.MythaiaLogger.debugEnabled = true
            com.mythaia.vpn.util.MythaiaLogger.backend = object : com.mythaia.vpn.util.LogBackend {
                override fun log(level: com.mythaia.vpn.util.MythaiaLogger.Level, category: String, message: String) =
                    println("LOG ${System.currentTimeMillis() % 100000} $level [$category] $message")
                override fun debug(category: String, message: String) =
                    println("LOG ${System.currentTimeMillis() % 100000} debug [$category] $message")
            }
        }
        for (path in files) {
            var bytes = File(path).readBytes()
            if (host != null) bytes = String(bytes, Charsets.UTF_8).replace("10.0.2.2", host).toByteArray()
            val input = ProtocolProbe.readInput(bytes)
            CertificatePolicy.setAllowInsecure(input.insecure)
            val out = File(System.getenv("MYTHAIA_MATRIX_OUT") ?: "build/matrix-results.tsv")
            // Also after parsing: a vmess:// link carries its address inside base64.
            val configs = ProtocolProbe.configurationsOf(File(path).name, input).map {
                if (host != null && it.serverAddress == "10.0.2.2") it.copy(serverAddress = host) else it
            }
            val gate = Semaphore(4)
            configs.map { config ->
                async(Dispatchers.IO) {
                    gate.withPermit {
                        val r = ProtocolProbe.probe(config, input.target)
                        val line = listOf(File(path).name, r.name, r.protocol, r.http, r.download, r.udp).joinToString("\t")
                        println("MATRIX\t$line")
                        synchronized(out) { out.appendText(line + "\n") }
                    }
                }
            }.awaitAll()
        }
        CertificatePolicy.setAllowInsecure(false)
    }
}
