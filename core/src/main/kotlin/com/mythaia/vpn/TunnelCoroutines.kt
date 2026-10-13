package com.mythaia.vpn

import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineExceptionHandler

private val logger = MythaiaLogger("Tunnel")

/**
 * The last line under the tunnel's long-lived coroutine scopes.
 *
 * An exception that escapes a coroutine launched straight into one of those
 * scopes goes to the thread's uncaught handler, and on Android that kills the
 * process — the whole VPN, every connection, for one flow's failure. Each
 * flow already closes itself on the errors it expects; this catches the ones
 * nobody expected (a server's 421 on a pooled stream did exactly that on
 * 2026-10-14), logs them, and lets the rest of the tunnel run.
 */
val tunnelCrashGuard: CoroutineExceptionHandler = CoroutineExceptionHandler { context, error ->
    logger.error("Uncaught in ${context[kotlinx.coroutines.CoroutineName]?.name ?: "a tunnel coroutine"}: $error")
}
