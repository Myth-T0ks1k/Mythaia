package com.mythaia.wear

import android.content.Context
import com.google.android.gms.wearable.CapabilityClient
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Node
import com.google.android.gms.wearable.Wearable
import kotlinx.coroutines.suspendCancellableCoroutine
import java.nio.charset.StandardCharsets
import kotlin.coroutines.resume

/** What the phone last said, as this app understands it. */
data class PhoneStatus(val state: State, val serverName: String) {

    enum class State {
        ON,
        OFF,

        /** VPN consent has never been granted; only the phone can ask for it. */
        NEEDS_PHONE,

        /** No server is selected over there. */
        NO_SERVER,

        /** The phone tried and could not. */
        FAILED,

        /** The phone did not answer — out of range, or the app is not installed. */
        UNREACHABLE,

        /** A command is in flight. */
        WORKING
    }

    companion object {
        val unknown = PhoneStatus(State.WORKING, "")

        /** Parses `state|name`, tolerating fields a later phone build adds. */
        fun parse(line: String): PhoneStatus {
            val parts = line.split('|')
            val state = when (parts.getOrNull(0)) {
                "on" -> State.ON
                "off" -> State.OFF
                "needs-phone" -> State.NEEDS_PHONE
                "no-server" -> State.NO_SERVER
                "failed" -> State.FAILED
                else -> State.UNREACHABLE
            }
            return PhoneStatus(state, parts.getOrNull(1).orEmpty())
        }
    }
}

/**
 * The link to the phone.
 *
 * Every exchange is a message rather than shared data: the watch is asking for
 * something to happen now and wants to know whether it did, which a synced data
 * item — delivered whenever the two happen to reconcile — cannot express.
 */
class PhoneLink(private val context: Context) {

    private val messageClient: MessageClient get() = Wearable.getMessageClient(context)

    /** Fired whenever the phone reports its status, solicited or not. */
    var onStatus: ((PhoneStatus) -> Unit)? = null

    private val listener = MessageClient.OnMessageReceivedListener { event: MessageEvent ->
        if (event.path == PATH_STATUS) {
            val line = String(event.data ?: ByteArray(0), StandardCharsets.UTF_8)
            onStatus?.invoke(PhoneStatus.parse(line))
        }
    }

    fun start() {
        messageClient.addListener(listener)
    }

    fun stop() {
        messageClient.removeListener(listener)
    }

    suspend fun requestStatus() {
        send(PATH_STATUS_REQUEST, "")
    }

    suspend fun connect() {
        send(PATH_COMMAND, COMMAND_CONNECT)
    }

    suspend fun disconnect() {
        send(PATH_COMMAND, COMMAND_DISCONNECT)
    }

    /**
     * Sends to every connected node.
     *
     * A watch is normally paired with one phone, but it can be reconnected to a
     * new one while the old node lingers, and the app only exists on the phone
     * that answers — so this does not try to guess which is the right one.
     */
    private suspend fun send(path: String, payload: String) {
        val nodes = connectedNodes()
        if (nodes.isEmpty()) {
            onStatus?.invoke(PhoneStatus(PhoneStatus.State.UNREACHABLE, ""))
            return
        }
        val bytes = payload.toByteArray(StandardCharsets.UTF_8)
        var delivered = false
        for (node in nodes) {
            val ok = suspendCancellableCoroutine { continuation ->
                messageClient.sendMessage(node.id, path, bytes)
                    .addOnSuccessListener { continuation.resume(true) }
                    .addOnFailureListener { continuation.resume(false) }
            }
            delivered = delivered || ok
        }
        if (!delivered) onStatus?.invoke(PhoneStatus(PhoneStatus.State.UNREACHABLE, ""))
    }

    private suspend fun connectedNodes(): List<Node> = suspendCancellableCoroutine { continuation ->
        Wearable.getNodeClient(context).connectedNodes
            .addOnSuccessListener { continuation.resume(it) }
            .addOnFailureListener { continuation.resume(emptyList()) }
    }

    private companion object {
        const val PATH_COMMAND = "/mythaia/command"
        const val PATH_STATUS_REQUEST = "/mythaia/status/request"
        const val PATH_STATUS = "/mythaia/status"

        const val COMMAND_CONNECT = "connect"
        const val COMMAND_DISCONNECT = "disconnect"

        @Suppress("unused")
        val capabilityFilter = CapabilityClient.FILTER_REACHABLE
    }
}
