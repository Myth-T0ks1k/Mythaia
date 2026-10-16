package com.mythaia.vpn

import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import com.mythaia.vpn.util.MythaiaLogger
import java.nio.charset.StandardCharsets

private val logger = MythaiaLogger("Wear")

/**
 * The phone's half of the watch app.
 *
 * The watch cannot run the tunnel — a VPN lives on the device whose traffic it
 * carries — so it sends a command here and gets the status back. Everything it
 * can ask for is something the tile can already do from outside the app, which
 * is why both go through [TunnelLauncher] rather than through the view model.
 *
 * A first connect still has to happen on the phone: VPN consent is an Activity
 * the system shows, and a watch has nowhere to show it. That answer comes back
 * as a status the watch can explain rather than as silence.
 */
class MythaiaWearListenerService : WearableListenerService() {

    override fun onMessageReceived(event: MessageEvent) {
        // Remember who asked, so a later change (the tunnel coming up after a
        // connect, or going down from the phone) reaches the watch unasked.
        rememberNode(applicationContext, event.sourceNodeId)
        when (event.path) {
            PATH_COMMAND -> {
                val command = String(event.data ?: ByteArray(0), StandardCharsets.UTF_8)
                handleCommand(command, event.sourceNodeId)
            }
            PATH_STATUS_REQUEST -> reply(event.sourceNodeId, status())
            else -> super.onMessageReceived(event)
        }
    }

    private fun handleCommand(command: String, node: String) {
        when (command) {
            COMMAND_DISCONNECT -> {
                TunnelLauncher.stop(this)
                // Reported straight away rather than after the service winds
                // down, so the watch face does not sit on a stale "on".
                reply(node, status(connectedOverride = false))
            }

            COMMAND_CONNECT -> {
                if (MythaiaVpnService.isActive) {
                    reply(node, status())
                    return
                }
                // A DNS lookup and a file write, so not on the callback thread.
                Thread({
                    val refusal = TunnelLauncher.startSelected(this)
                    // A clean start is still in progress at this point; the
                    // state listener pushes "on" once the tunnel is really up,
                    // and the failure listener "failed" if it never is.
                    if (refusal != null) reply(node, status(refusal = refusal))
                }, "wear-connect").apply { isDaemon = true }.start()
            }

            else -> logger.warning("[Wear] Unknown command: $command")
        }
    }

    /**
     * `state|name`.
     *
     * Deliberately a flat string: the watch and the phone are two APKs that
     * must be updatable apart from each other, and a positional line is far
     * harder to break across versions than a shared serialised class. A reader
     * that wants more fields later can take them off the end.
     */
    private fun status(
        connectedOverride: Boolean? = null,
        refusal: TunnelLauncher.Refusal? = null
    ): String {
        val state = when {
            refusal == TunnelLauncher.Refusal.NEEDS_CONSENT -> STATE_NEEDS_PHONE
            refusal == TunnelLauncher.Refusal.NO_SELECTION -> STATE_NO_SERVER
            refusal != null -> STATE_FAILED
            connectedOverride == false -> STATE_OFF
            MythaiaVpnService.isActive -> STATE_ON
            else -> STATE_OFF
        }
        return statusLine(this, state)
    }

    private fun reply(node: String, payload: String) {
        try {
            Wearable.getMessageClient(this)
                .sendMessage(node, PATH_STATUS, payload.toByteArray(StandardCharsets.UTF_8))
        } catch (e: Exception) {
            logger.warning("[Wear] Could not answer $node: ${e.message ?: e}")
        }
    }

    companion object {
        @Volatile
        private var lastNode: String? = null
        private var listening = false

        /** Registers, once, for tunnel state changes to forward to [lastNode]. */
        private fun rememberNode(context: android.content.Context, node: String) {
            lastNode = node
            synchronized(this) {
                if (listening) return
                listening = true
                MythaiaVpnService.addStateListener {
                    push(context, if (MythaiaVpnService.isActive) STATE_ON else STATE_OFF)
                }
                // A start that got past TunnelLauncher and failed before the
                // tunnel came up (DNS, a refused TUN) never changes the state,
                // so the listener above stays silent and the watch waited out
                // its timeout into "No phone".
                MythaiaVpnService.addStartFailureListener { push(context, STATE_FAILED) }
            }
        }

        /** Sends [state] to the watch that last spoke to us, if any. */
        private fun push(context: android.content.Context, state: String) {
            val target = lastNode ?: return
            try {
                Wearable.getMessageClient(context)
                    .sendMessage(target, PATH_STATUS, statusLine(context, state).toByteArray(StandardCharsets.UTF_8))
            } catch (e: Exception) {
                logger.warning("[Wear] Could not push status: ${e.message ?: e}")
            }
        }

        /**
         * [state] with the tunnel's own name where it is up, so the watch is
         * not left showing a selection the running session no longer matches.
         */
        private fun statusLine(context: android.content.Context, state: String): String {
            val name = (MythaiaVpnService.activeServerName ?: TunnelLauncher.selectedName(context))
                .orEmpty()
                .replace('|', ' ')
            return "$state|$name"
        }

        const val PATH_COMMAND = "/mythaia/command"
        const val PATH_STATUS_REQUEST = "/mythaia/status/request"
        const val PATH_STATUS = "/mythaia/status"

        const val COMMAND_CONNECT = "connect"
        const val COMMAND_DISCONNECT = "disconnect"

        const val STATE_ON = "on"
        const val STATE_OFF = "off"
        const val STATE_NEEDS_PHONE = "needs-phone"
        const val STATE_NO_SERVER = "no-server"
        const val STATE_FAILED = "failed"
    }
}
