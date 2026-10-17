package com.mythaia.desktop.tun

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The structures the utun code hands the macOS kernel, byte for byte. They
 * cannot be exercised without a Mac and root, and a wrong offset there is an
 * interface that never appears, so the layouts are pinned here.
 */
class UtunLayoutTest {

    @Test
    fun `CTLIOCGINFO is the ioctl macro for ctl_info`() {
        assertEquals(100, UtunLayout.CTL_INFO_SIZE)
        assertEquals(0xC0644E03L, UtunLayout.CTLIOCGINFO)
    }

    @Test
    fun `ctl_info carries the control name after a zero id`() {
        val info = UtunLayout.ctlInfo()
        assertEquals(100, info.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), info.copyOfRange(0, 4))
        val name = "com.apple.net.utun_control".toByteArray()
        assertArrayEquals(name, info.copyOfRange(4, 4 + name.size))
        assertEquals(0.toByte(), info[4 + name.size])
        // What the kernel writes back is read as a little-endian word.
        info[0] = 0x2A; info[1] = 0x01
        assertEquals(0x012A, UtunLayout.ctlId(info))
    }

    @Test
    fun `sockaddr_ctl is 32 bytes with family, sysaddr, id and unit in place`() {
        val address = UtunLayout.sockaddrCtl(ctlId = 0x01020304, unit = 0)
        assertEquals(32, address.size)
        assertEquals(32, address[0].toInt())                 // sc_len
        assertEquals(32, address[1].toInt())                 // sc_family = AF_SYSTEM
        assertArrayEquals(byteArrayOf(2, 0), address.copyOfRange(2, 4))                 // ss_sysaddr = AF_SYS_CONTROL
        assertArrayEquals(byteArrayOf(4, 3, 2, 1), address.copyOfRange(4, 8))           // sc_id
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), address.copyOfRange(8, 12))          // sc_unit 0: next free
        assertArrayEquals(ByteArray(20), address.copyOfRange(12, 32))                  // sc_reserved
        assertArrayEquals(byteArrayOf(6, 0, 0, 0), UtunLayout.sockaddrCtl(1, unit = 6).copyOfRange(8, 12))
    }

    @Test
    fun `every packet gets its address family in network order`() {
        val v4 = byteArrayOf(0x45, 0, 0, 20) + ByteArray(16)
        val v6 = byteArrayOf(0x60, 0, 0, 0) + ByteArray(36)
        assertArrayEquals(byteArrayOf(0, 0, 0, 2), UtunLayout.headerFor(v4[0]))
        assertArrayEquals(byteArrayOf(0, 0, 0, 30), UtunLayout.headerFor(v6[0]))
        assertNull(UtunLayout.headerFor(0x00))

        val framed = UtunLayout.frame(v4, v4.size)!!
        assertEquals(v4.size + 4, framed.size)
        assertArrayEquals(byteArrayOf(0, 0, 0, 2), framed.copyOfRange(0, 4))
        assertArrayEquals(v4, framed.copyOfRange(4, framed.size))
        assertEquals(UtunLayout.AF_INET, UtunLayout.familyOf(framed))
        assertEquals(UtunLayout.AF_INET6, UtunLayout.familyOf(UtunLayout.frame(v6, 10)!!))
        assertEquals(14, UtunLayout.frame(v6, 10)!!.size)
        assertNull(UtunLayout.familyOf(byteArrayOf(2, 0, 0, 0)))           // host order would be wrong
        assertNull(UtunLayout.frame(byteArrayOf(0x10, 0), 2))
    }

    @Test
    fun `the interface name stops at the terminator`() {
        val bytes = "utun7".toByteArray() + ByteArray(11)
        assertEquals("utun7", UtunLayout.ifName(bytes, 6))
        assertEquals("utun12", UtunLayout.ifName("utun12".toByteArray() + ByteArray(10), 16))
        assertEquals("utun", UtunLayout.ifName("utun12".toByteArray(), 4))
    }

    @Test
    fun `pollfd waits for input on the descriptor`() {
        assertArrayEquals(byteArrayOf(9, 0, 0, 0, 1, 0, 0, 0), UtunLayout.pollFd(9))
        assertArrayEquals(byteArrayOf(0x34, 0x12, 0, 0, 1, 0, 0, 0), UtunLayout.pollFd(0x1234))
    }
}
