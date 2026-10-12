package com.mythaia.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import kotlin.concurrent.thread

/**
 * Debug builds only: call-shaped UDP through whatever tunnel is up, measured
 * from inside the app's own process — which is inside its VPN, and which an
 * instrumentation run would kill (am instrument force-stops the package, and
 * the tunnel with it).
 *
 * Each target gets a 50-packets-per-second STUN stream — small packets like
 * voice, and 1100-byte ones like video — all targets at once, as a call client
 * probes several relays. Per stream: replies, loss, median and p95 round trip.
 *
 *     adb shell am broadcast -n com.mythaia/.debug.UdpSimReceiver
 *         --es targets stun.l.google.com:19302,stun1.l.google.com:19302 --ei seconds 6
 *     adb exec-out run-as com.mythaia cat files/matrix/udpsim.txt
 */
class UdpSimReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val targets = intent.getStringExtra("targets")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
        if (targets.isEmpty()) return
        val seconds = intent.getIntExtra("seconds", 6)
        val dir = java.io.File(context.filesDir, "matrix").apply { mkdirs() }
        val out = java.io.File(dir, "udpsim.txt")
        out.delete()
        // The broadcast returns at once; the process stays up for the VPN service.
        thread(name = "udpsim") {
            val results = java.util.Collections.synchronizedList(mutableListOf<String>())
            targets.flatMap { target ->
                listOf(64, 1100).map { size -> thread(name = "udp-$target-$size") { results += stream(target, size, seconds) } }
            }.forEach { it.join() }
            results.sorted().forEach { Log.i("UDPSIM", it) }
            out.writeText(results.sorted().joinToString("\n", postfix = "\n"))
        }
    }

    private fun stream(target: String, size: Int, seconds: Int): String {
        val host = target.substringBeforeLast(':')
        val port = target.substringAfterLast(':').toInt()
        val address = runCatching { InetAddress.getByName(host) }.getOrElse { return "$target ${size}B: DNS failed ${it.message}" }
        val random = SecureRandom()
        val socket = DatagramSocket()
        socket.soTimeout = 200
        val sentAt = java.util.concurrent.ConcurrentHashMap<String, Long>()
        val rtts = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val total = seconds * 50
        val sending = java.util.concurrent.atomic.AtomicBoolean(true)
        val receiver = thread {
            val buffer = ByteArray(2048)
            while (sending.get() || sentAt.isNotEmpty()) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (_: SocketTimeoutException) {
                    if (!sending.get()) break else continue
                } catch (_: Exception) {
                    break
                }
                if (packet.length < 20) continue
                val id = buffer.copyOfRange(8, 20).joinToString("") { "%02x".format(it) }
                sentAt.remove(id)?.let { rtts += (System.nanoTime() - it) / 1_000_000 }
            }
        }
        for (i in 0 until total) {
            val tid = ByteArray(12).also(random::nextBytes)
            val body = ByteArray(maxOf(20, size))
            // Binding request, magic cookie, transaction id.
            body[0] = 0; body[1] = 1
            body[4] = 0x21; body[5] = 0x12; body[6] = 0xa4.toByte(); body[7] = 0x42
            tid.copyInto(body, 8)
            if (size > 24) {
                // A comprehension-optional attribute (0x8022 SOFTWARE-like range is
                // ignored by servers): padding to make the packet video-sized.
                val attrLen = ((size - 24) / 4) * 4
                body[20] = 0x80.toByte(); body[21] = 0x2f
                body[22] = (attrLen shr 8).toByte(); body[23] = attrLen.toByte()
                val msgLen = 4 + attrLen
                body[2] = (msgLen shr 8).toByte(); body[3] = msgLen.toByte()
            }
            val packetLength = if (size > 24) 20 + 4 + ((size - 24) / 4) * 4 else 20
            sentAt[tid.joinToString("") { "%02x".format(it) }] = System.nanoTime()
            runCatching { socket.send(DatagramPacket(body, packetLength, address, port)) }
            Thread.sleep(20)
        }
        Thread.sleep(1500)
        sending.set(false)
        receiver.join(3000)
        socket.close()
        val got = rtts.size
        val sorted = rtts.sorted()
        val median = sorted.getOrNull(sorted.size / 2) ?: -1
        val p95 = sorted.getOrNull((sorted.size * 95) / 100) ?: -1
        val loss = 100.0 * (total - got) / total
        return "$target ${size}B: $got/$total replies, loss ${"%.1f".format(loss)}%, rtt median ${median}ms p95 ${p95}ms"
    }
}
