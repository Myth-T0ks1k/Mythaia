package com.mythaia.desktop.tun

import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import java.io.IOException

/**
 * libc as the macOS TUN code needs it. Loaded on first use, so nothing on
 * Windows ever looks for these symbols. `size_t` and `ssize_t` are `Long`:
 * both Mac architectures are LP64.
 */
@Suppress("FunctionName")
internal interface MacLibc : Library {
    fun socket(domain: Int, type: Int, protocol: Int): Int

    /**
     * `int ioctl(int, unsigned long, ...)`. Declared variadic on purpose:
     * on Apple silicon the variadic tail goes on the stack, not in a
     * register, and JNA only does that for a Java varargs method.
     */
    fun ioctl(fd: Int, request: Long, vararg args: Any?): Int
    fun connect(fd: Int, address: Pointer, length: Int): Int
    fun getsockopt(fd: Int, level: Int, option: Int, value: Pointer, length: IntByReference): Int
    fun recv(fd: Int, buffer: Pointer, length: Long, flags: Int): Long
    fun write(fd: Int, buffer: Pointer, count: Long): Long
    fun poll(fds: Pointer, count: Int, timeoutMs: Int): Int
    fun close(fd: Int): Int
    fun geteuid(): Int
    fun strerror(errno: Int): String?

    companion object {
        val INSTANCE: MacLibc by lazy { Native.load("c", MacLibc::class.java) }
    }
}

/**
 * The byte layouts the utun code exchanges with the kernel, apart from the
 * calls so they are tested on any machine. Both Mac architectures are
 * little-endian, so the structures' native integers are written that way;
 * the address-family word in front of every packet is in network order.
 */
internal object UtunLayout {
    const val PF_SYSTEM = 32
    const val AF_SYSTEM = 32
    const val SOCK_DGRAM = 2
    const val SYSPROTO_CONTROL = 2
    const val AF_SYS_CONTROL = 2
    const val UTUN_OPT_IFNAME = 2
    const val UTUN_CONTROL_NAME = "com.apple.net.utun_control"

    /** `struct ctl_info { u_int32_t ctl_id; char ctl_name[96]; }`. */
    const val MAX_KCTL_NAME = 96
    const val CTL_INFO_SIZE = 4 + MAX_KCTL_NAME

    /** `CTLIOCGINFO`, `_IOWR('N', 3, struct ctl_info)`. */
    val CTLIOCGINFO: Long = iowr('N', 3, CTL_INFO_SIZE)

    /** `struct sockaddr_ctl`: len, family, sysaddr, id, unit, five reserved words. */
    const val SOCKADDR_CTL_SIZE = 32
    const val IFNAMSIZ = 16

    const val AF_INET = 2
    const val AF_INET6 = 30
    /** The address-family word utun puts in front of every packet. */
    const val HEADER = 4

    /** `struct pollfd { int fd; short events; short revents; }`. */
    const val POLLFD_SIZE = 8
    const val POLLIN = 0x0001
    const val POLLERR = 0x0008
    const val POLLHUP = 0x0010
    const val POLLNVAL = 0x0020

    const val MSG_DONTWAIT = 0x80
    const val EPERM = 1
    const val EINTR = 4
    const val EACCES = 13
    const val EAGAIN = 35

    private val V4_HEADER = byteArrayOf(0, 0, 0, AF_INET.toByte())
    private val V6_HEADER = byteArrayOf(0, 0, 0, AF_INET6.toByte())

    /** BSD `_IOWR`: in and out, the argument's size in bits 16-28, the group and the number. */
    fun iowr(group: Char, number: Int, size: Int): Long =
        0xC0000000L or ((size.toLong() and 0x1FFF) shl 16) or (group.code.toLong() shl 8) or number.toLong()

    /** A `ctl_info` asking for [name]'s id; the kernel fills `ctl_id` in. */
    fun ctlInfo(name: String = UTUN_CONTROL_NAME): ByteArray {
        val bytes = name.toByteArray(Charsets.US_ASCII)
        require(bytes.size < MAX_KCTL_NAME) { "control name too long" }
        val out = ByteArray(CTL_INFO_SIZE)
        bytes.copyInto(out, 4)
        return out
    }

    /** The `ctl_id` the kernel wrote into a `ctl_info`. */
    fun ctlId(info: ByteArray): Int = readIntLe(info, 0)

    /** A `sockaddr_ctl` for control [ctlId]; unit 0 asks for the next free utun. */
    fun sockaddrCtl(ctlId: Int, unit: Int = 0): ByteArray {
        val out = ByteArray(SOCKADDR_CTL_SIZE)
        out[0] = SOCKADDR_CTL_SIZE.toByte()
        out[1] = AF_SYSTEM.toByte()
        writeShortLe(out, 2, AF_SYS_CONTROL)
        writeIntLe(out, 4, ctlId)
        writeIntLe(out, 8, unit)
        return out
    }

    /** The interface name `UTUN_OPT_IFNAME` returned: [length] bytes, NUL-terminated. */
    fun ifName(bytes: ByteArray, length: Int): String {
        val end = (0 until minOf(length, bytes.size)).firstOrNull { bytes[it] == 0.toByte() } ?: minOf(length, bytes.size)
        return String(bytes, 0, end, Charsets.US_ASCII)
    }

    /** The family word for a packet whose first byte is [first], or null when it is neither IPv4 nor IPv6. */
    fun headerFor(first: Byte): ByteArray? = when ((first.toInt() shr 4) and 0x0F) {
        4 -> V4_HEADER
        6 -> V6_HEADER
        else -> null
    }

    /** [packet]'s first [length] bytes with the family word in front, as utun takes them. */
    fun frame(packet: ByteArray, length: Int): ByteArray? {
        val header = headerFor(packet[0]) ?: return null
        val out = ByteArray(HEADER + length)
        header.copyInto(out)
        packet.copyInto(out, HEADER, 0, length)
        return out
    }

    /** The family a frame read from utun names (network order), or null when it is not one of ours. */
    fun familyOf(frame: ByteArray): Int? {
        if (frame.size < HEADER) return null
        val family = ((frame[0].toInt() and 0xFF) shl 24) or ((frame[1].toInt() and 0xFF) shl 16) or
            ((frame[2].toInt() and 0xFF) shl 8) or (frame[3].toInt() and 0xFF)
        return family.takeIf { it == AF_INET || it == AF_INET6 }
    }

    /** One `pollfd` waiting for [fd] to be readable. */
    fun pollFd(fd: Int): ByteArray {
        val out = ByteArray(POLLFD_SIZE)
        writeIntLe(out, 0, fd)
        writeShortLe(out, 4, POLLIN)
        return out
    }

    private fun writeIntLe(out: ByteArray, offset: Int, value: Int) {
        for (i in 0 until 4) out[offset + i] = (value ushr (8 * i)).toByte()
    }

    private fun writeShortLe(out: ByteArray, offset: Int, value: Int) {
        out[offset] = value.toByte()
        out[offset + 1] = (value ushr 8).toByte()
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or ((bytes[offset + 3].toInt() and 0xFF) shl 24)
}

/**
 * A macOS utun interface: a `PF_SYSTEM` socket connected to the kernel's
 * utun control. The system names it (`utun5`) and removes it, with every
 * route on it, when the socket closes — also when the process dies, so a
 * crash leaves no interface behind. Creating one needs root.
 *
 * Every packet read or written carries a 4-byte address-family word in
 * front; this class adds and strips it, so the engine sees bare IP packets.
 */
class MacUtun private constructor(private val libc: MacLibc, @Volatile private var fd: Int, override val name: String) : TunDevice {
    @Volatile
    private var open = true
    private val sendLock = Any()
    private val sendBuffer = Memory((MAX_PACKET_SIZE + UtunLayout.HEADER).toLong())

    /** The socket passes packets from the moment it is connected. */
    override fun start() {}

    /**
     * Waits for packets with `poll` (so [keepRunning] is checked every
     * [READ_WAIT_MS]) and then drains what is queued without blocking, up to
     * [batchSize] per hand-over.
     */
    override fun readLoop(keepRunning: () -> Boolean, batchSize: Int, onBatch: (List<ByteArray>) -> Unit) {
        val pollFd = Memory(UtunLayout.POLLFD_SIZE.toLong())
        val capacity = MAX_PACKET_SIZE + UtunLayout.HEADER
        val buffer = Memory(capacity.toLong())
        val batch = ArrayList<ByteArray>(batchSize)
        loop@ while (keepRunning() && open) {
            val socket = fd
            if (socket < 0) break
            pollFd.write(0, UtunLayout.pollFd(socket), 0, UtunLayout.POLLFD_SIZE)
            val ready = libc.poll(pollFd, 1, READ_WAIT_MS)
            if (ready < 0) {
                val errno = Native.getLastError()
                if (errno == UtunLayout.EINTR) continue
                logger.warning("poll on $name failed: ${errorText(errno)}")
                break
            }
            if (ready == 0) continue
            val events = pollFd.getShort(6).toInt()
            if (events and UtunLayout.POLLIN == 0 && events and (UtunLayout.POLLERR or UtunLayout.POLLHUP or UtunLayout.POLLNVAL) != 0) {
                logger.warning("$name closed under the reader (events $events)")
                break
            }
            while (batch.size < batchSize) {
                val n = libc.recv(socket, buffer, capacity.toLong(), UtunLayout.MSG_DONTWAIT)
                if (n < 0) {
                    val errno = Native.getLastError()
                    if (errno == UtunLayout.EAGAIN || errno == UtunLayout.EINTR) break
                    if (batch.isNotEmpty()) onBatch(ArrayList(batch))
                    logger.warning("recv on $name failed: ${errorText(errno)}")
                    break@loop
                }
                if (n <= UtunLayout.HEADER) continue
                batch.add(buffer.getByteArray(UtunLayout.HEADER.toLong(), (n - UtunLayout.HEADER).toInt()))
            }
            if (batch.isNotEmpty()) {
                onBatch(ArrayList(batch))
                batch.clear()
            }
        }
    }

    /** Writes one packet with its family word; false when it was not an IP packet or the write failed. */
    override fun send(packet: ByteArray, length: Int): Boolean {
        if (!open || length <= 0 || length > MAX_PACKET_SIZE) return false
        val header = UtunLayout.headerFor(packet[0]) ?: return false
        synchronized(sendLock) {
            val socket = fd
            if (socket < 0) return false
            sendBuffer.write(0, header, 0, UtunLayout.HEADER)
            sendBuffer.write(UtunLayout.HEADER.toLong(), packet, 0, length)
            val total = (length + UtunLayout.HEADER).toLong()
            return libc.write(socket, sendBuffer, total) == total
        }
    }

    override fun stop() {
        open = false
    }

    override fun close() {
        open = false
        synchronized(sendLock) {
            val socket = fd
            if (socket < 0) return
            fd = -1
            libc.close(socket)
        }
        logger.info("$name closed")
    }

    companion object {
        private val logger = MythaiaLogger("Utun")
        const val MAX_PACKET_SIZE = 0xFFFF
        private const val READ_WAIT_MS = 250

        /** Creates the next free utun interface. Needs root. */
        @Throws(IOException::class)
        fun open(): MacUtun {
            val libc = MacLibc.INSTANCE
            val fd = libc.socket(UtunLayout.PF_SYSTEM, UtunLayout.SOCK_DGRAM, UtunLayout.SYSPROTO_CONTROL)
            if (fd < 0) throw IOException("socket(PF_SYSTEM) failed: ${errorText(Native.getLastError())}")
            try {
                val info = Memory(UtunLayout.CTL_INFO_SIZE.toLong())
                info.write(0, UtunLayout.ctlInfo(), 0, UtunLayout.CTL_INFO_SIZE)
                if (libc.ioctl(fd, UtunLayout.CTLIOCGINFO, info) < 0) {
                    throw IOException("The utun control is not available: ${errorText(Native.getLastError())}")
                }
                val id = UtunLayout.ctlId(info.getByteArray(0, 4))
                val address = Memory(UtunLayout.SOCKADDR_CTL_SIZE.toLong())
                address.write(0, UtunLayout.sockaddrCtl(id), 0, UtunLayout.SOCKADDR_CTL_SIZE)
                if (libc.connect(fd, address, UtunLayout.SOCKADDR_CTL_SIZE) < 0) {
                    val errno = Native.getLastError()
                    throw IOException(
                        if (errno == UtunLayout.EPERM || errno == UtunLayout.EACCES) "Creating a utun interface needs root"
                        else "Could not create a utun interface: ${errorText(errno)}"
                    )
                }
                val nameBuffer = Memory(UtunLayout.IFNAMSIZ.toLong())
                nameBuffer.clear()
                val length = IntByReference(UtunLayout.IFNAMSIZ)
                if (libc.getsockopt(fd, UtunLayout.SYSPROTO_CONTROL, UtunLayout.UTUN_OPT_IFNAME, nameBuffer, length) < 0) {
                    throw IOException("The utun interface has no name: ${errorText(Native.getLastError())}")
                }
                val name = UtunLayout.ifName(nameBuffer.getByteArray(0, UtunLayout.IFNAMSIZ), length.value)
                logger.info("Created $name")
                return MacUtun(libc, fd, name)
            } catch (e: Throwable) {
                libc.close(fd)
                throw e
            }
        }

        /** Whether this process runs as root. */
        fun isRoot(): Boolean = runCatching { MacLibc.INSTANCE.geteuid() == 0 }.getOrDefault(false)

        private fun errorText(errno: Int): String {
            val text = runCatching { MacLibc.INSTANCE.strerror(errno) }.getOrNull()
            return if (text.isNullOrBlank()) "errno $errno" else "$text (errno $errno)"
        }
    }
}
