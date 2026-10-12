package com.mythaia.vpn

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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
import org.junit.runner.RunWith
import java.io.File

/**
 * Dials every configuration it is given through the real protocol stack on
 * the device and reports, per server, whether an HTTP request, a download
 * with a checked hash and a UDP round trip got through (see [ProtocolProbe]).
 *
 * Inputs are files in the app's private files dir, `matrix/` - a debug build
 * lets `adb exec-in run-as com.mythaia` write there. Every `*.txt`/`*.json`
 * is parsed as a subscription body, every `*.conf` as a WireGuard profile;
 * header lines are described in [ProtocolProbe.readInput]. Results go to
 * logcat (tag MATRIX) and `matrix/results.tsv`. Nothing is asserted: the
 * report is the product. With no inputs the test is skipped, so
 * `connectedDebugAndroidTest` stays green on a bare device.
 *
 * `scripts/android-matrix.py` pushes inputs, runs this and prints the table.
 */
@RunWith(AndroidJUnit4::class)
class ProtocolMatrixTest {

    @Test
    fun everyServerInTheInputs() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(context.filesDir, "matrix")
        val inputs = dir.listFiles { f -> f.isFile && f.name.substringAfterLast('.') in setOf("txt", "json", "conf") }
            ?.sortedBy { it.name }.orEmpty()
        assumeTrue("no inputs in $dir", inputs.isNotEmpty())

        val lines = mutableListOf("source\tname\tprotocol\thttp\tdownload\tudp")
        for (file in inputs) {
            val input = ProtocolProbe.readInput(file.readBytes())
            CertificatePolicy.setAllowInsecure(input.insecure)
            val configs = try {
                ProtocolProbe.configurationsOf(file.name, input)
            } catch (e: Exception) {
                lines += "${file.name}\t-\t-\tPARSE FAIL ${e.message}\t-\t-"
                continue
            }
            Log.i("MATRIX", "${file.name}: ${configs.size} servers")
            val gate = Semaphore(4)
            val reports = configs.map { config ->
                async(Dispatchers.IO) { gate.withPermit { ProtocolProbe.probe(config, input.target) } }
            }.awaitAll()
            reports.forEach { r -> lines += listOf(file.name, r.name, r.protocol, r.http, r.download, r.udp).joinToString("\t") }
        }
        CertificatePolicy.setAllowInsecure(false)
        File(dir, "results.tsv").writeText(lines.joinToString("\n", postfix = "\n"))
        lines.forEach { Log.i("MATRIX", it) }
    }
}
