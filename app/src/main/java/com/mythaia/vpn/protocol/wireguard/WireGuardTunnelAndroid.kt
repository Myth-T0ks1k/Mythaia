package com.mythaia.vpn.protocol.wireguard

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.OsConstants
import java.io.FileInputStream
import java.io.FileOutputStream

/** The VPN's TUN file descriptor as the tunnel's [PacketDevice]. */
class FdPacketDevice(fd: ParcelFileDescriptor) : PacketDevice {
    private val input = FileInputStream(fd.fileDescriptor)
    private val output = FileOutputStream(fd.fileDescriptor)

    @Volatile
    private var closed = false

    override fun read(buffer: ByteArray): Int {
        val n = try {
            input.read(buffer)
        } catch (e: Exception) {
            if (closed) return -1
            val cause = e.cause
            if (cause is ErrnoException &&
                (cause.errno == OsConstants.EAGAIN || cause.errno == OsConstants.EINTR)
            ) {
                return 0
            }
            throw e
        }
        if (n > 0) return n
        return if (closed) -1 else 0
    }

    override fun write(packet: ByteArray, length: Int) = output.write(packet, 0, length)

    override fun close() {
        closed = true
        runCatching { input.close() }
        runCatching { output.close() }
    }
}

/** Runs the tunnel over the VPN's TUN; the socket to the peer goes through VpnService.protect. */
fun WireGuardTunnel.start(fd: ParcelFileDescriptor) = start(FdPacketDevice(fd))
