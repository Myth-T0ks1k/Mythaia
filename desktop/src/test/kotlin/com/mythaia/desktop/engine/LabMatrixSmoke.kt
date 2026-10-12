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
        for (path in files) {
            var bytes = File(path).readBytes()
            if (host != null) bytes = String(bytes, Charsets.UTF_8).replace("10.0.2.2", host).toByteArray()
            val input = ProtocolProbe.readInput(bytes)
            CertificatePolicy.setAllowInsecure(input.insecure)
            val out = File(System.getenv("MYTHAIA_MATRIX_OUT") ?: "build/matrix-results.tsv")
            val configs = ProtocolProbe.configurationsOf(File(path).name, input)
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
