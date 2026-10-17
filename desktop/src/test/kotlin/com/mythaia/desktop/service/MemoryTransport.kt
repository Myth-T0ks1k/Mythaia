package com.mythaia.desktop.service

import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * A [ServiceTransport] inside one process, for testing [ServiceCore] with no
 * pipe or socket: [exchange] hands the service a connection made of two
 * queues and waits for the reply line.
 */
class MemoryTransport : ServiceTransport {
    private val pending = LinkedBlockingQueue<ServiceConnection>()

    @Volatile
    private var closed = false

    override val address: String = "memory"

    override fun accept(): ServiceConnection {
        while (true) {
            if (closed) throw IOException("transport closed")
            pending.poll(50, TimeUnit.MILLISECONDS)?.let { return it }
        }
    }

    override fun exchange(line: String, timeoutMs: Long): String? {
        if (closed) return null
        val toService = LinkedBlockingQueue<Any>()
        val toWindow = LinkedBlockingQueue<String>()
        pending.put(object : ServiceConnection {
            override fun readLine(): String? = toService.take().let { if (it === END) null else it as String }
            override fun writeLine(text: String) = toWindow.put(text)
            override fun close() {}
        })
        toService.put(line)
        val reply = toWindow.poll(timeoutMs, TimeUnit.MILLISECONDS)
        toService.put(END)
        return reply
    }

    override fun close() {
        closed = true
    }

    private companion object {
        val END = Any()
    }
}
