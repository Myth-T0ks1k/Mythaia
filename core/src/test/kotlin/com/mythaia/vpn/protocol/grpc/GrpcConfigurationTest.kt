package com.mythaia.vpn.protocol.grpc

import org.junit.Assert.assertEquals
import org.junit.Test

class GrpcConfigurationTest {

    @Test
    fun `the service name is escaped as Go's PathEscape does, since that is what the server expects`() {
        assertEquals("/my@svc/Tun", GrpcConfiguration(serviceName = "my@svc").resolvedPath())
        assertEquals("/a%20b%2A/Tun", GrpcConfiguration(serviceName = "a b*").resolvedPath())
        assertEquals("/x%2Fy/Tun", GrpcConfiguration(serviceName = "x/y").resolvedPath())
        // Unreserved and the sub-delims Go keeps in a path segment.
        assertEquals(
            "/~u.n-d_r$&+:=@/TunMulti",
            GrpcConfiguration(serviceName = "~u.n-d_r$&+:=@", multiMode = true).resolvedPath()
        )
        // The sub-delims it does not, and UTF-8 byte by byte, uppercase.
        assertEquals("/%D0%BF%3B%2C%3F%25/Tun", GrpcConfiguration(serviceName = "п;,?%").resolvedPath())
    }

    @Test
    fun `a custom path escapes each segment on its own`() {
        assertEquals("/a%20b/c/Stream", GrpcConfiguration(serviceName = "/a b/c/Stream").resolvedPath())
        assertEquals("/svc/Tun", GrpcConfiguration(serviceName = "/svc/Tun|TunMulti").resolvedPath())
        assertEquals("/svc/TunMulti", GrpcConfiguration(serviceName = "/svc/Tun|TunMulti", multiMode = true).resolvedPath())
        // A lone leading slash, as Xray reads it: no service part, the rest from index 2.
        assertEquals("/un", GrpcConfiguration(serviceName = "/Tun").resolvedPath())
    }

    @Test
    fun `the default service name is unchanged by escaping`() {
        assertEquals(
            "/${GrpcConfiguration.DEFAULT_SERVICE_NAME}/Tun",
            GrpcConfiguration().resolvedPath()
        )
    }
}
