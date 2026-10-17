package com.mythaia.desktop.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit
import javax.xml.parsers.DocumentBuilderFactory

/**
 * The LaunchDaemon's plist and the root scripts that install and remove it.
 * They run as root with one password prompt, so their text is pinned: the
 * quoting of a path with spaces and quotes above all.
 */
class MacDaemonTest {

    private val launcher = MacDaemon.launcherPath("Mythaia Pro")

    @Test
    fun `the plist runs the root-owned copy with --service`() {
        assertEquals("/Library/Application Support/Mythaia/Service/Mythaia Pro.app/Contents/MacOS/Mythaia Pro", launcher)
        val text = MacDaemon.plist(launcher)
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        val doc = factory.newDocumentBuilder().parse(text.byteInputStream())
        val dict = doc.documentElement.getElementsByTagName("dict").item(0)
        val entries = LinkedHashMap<String, org.w3c.dom.Node>()
        var key: String? = null
        val children = dict.childNodes
        for (i in 0 until children.length) {
            val node = children.item(i)
            if (node.nodeType != org.w3c.dom.Node.ELEMENT_NODE) continue
            if (node.nodeName == "key") key = node.textContent else key?.let { entries[it] = node; key = null }
        }
        assertEquals("com.mythaia.desktop.service", entries["Label"]!!.textContent)
        val args = entries["ProgramArguments"]!!.childNodes.let { list ->
            (0 until list.length).map { list.item(it) }.filter { it.nodeName == "string" }.map { it.textContent }
        }
        assertEquals(listOf(launcher, "--service"), args)
        assertEquals("true", entries["RunAtLoad"]!!.nodeName)
        assertTrue(entries["KeepAlive"]!!.textContent.contains("SuccessfulExit"))
        assertEquals("/Library/Application Support/Mythaia/service.stderr.log", entries["StandardErrorPath"]!!.textContent)
    }

    @Test
    fun `characters XML gives meaning to are escaped in the plist`() {
        val text = MacDaemon.plist("/Applications/R&D <test>/x")
        assertTrue(text.contains("<string>/Applications/R&amp;D &lt;test&gt;/x</string>"))
    }

    @Test
    fun `install copies the bundle as root, swaps it in and bootstraps the daemon`() {
        val script = MacDaemon.installScript("/Users/someone/Apps/Mythaia Pro.app", "Mythaia Pro")
        val lines = script.lines()
        assertEquals("set -e", lines.first())
        val order = listOf(
            "/bin/launchctl bootout \"system/\$label\" 2>/dev/null || true",
            "/bin/cp -RL '/Users/someone/Apps/Mythaia Pro.app' \"\$app.new\"",
            "/usr/sbin/chown -R root:wheel \"\$app.new\"",
            "/bin/chmod -R go-w \"\$app.new\"",
            "/bin/mv \"\$app.new\" \"\$app\"",
            "[ -x '/Library/Application Support/Mythaia/Service/Mythaia Pro.app/Contents/MacOS/Mythaia Pro' ]",
            "/bin/mv -f \"\$plist.new\" \"\$plist\"",
            "/bin/launchctl bootstrap system \"\$plist\" || { /bin/sleep 2; /bin/launchctl bootstrap system \"\$plist\"; }"
        )
        val positions = order.map { line -> lines.indexOf(line).also { assertTrue("missing: $line", it >= 0) } }
        assertEquals(positions.sorted(), positions)
        assertTrue(lines.contains("app='/Library/Application Support/Mythaia/Service/Mythaia Pro.app'"))
        assertTrue(lines.contains("plist='/Library/LaunchDaemons/com.mythaia.desktop.service.plist'"))
        assertTrue(lines.any { it.startsWith("printf '%s' '<?xml") })
    }

    @Test
    fun `a quote in the bundle's path cannot end the shell word`() {
        val script = MacDaemon.installScript("/Users/someone/it's here/Mythaia Pro.app", "Mythaia Pro")
        assertTrue(script.contains("/bin/cp -RL '/Users/someone/it'\\''s here/Mythaia Pro.app' \"\$app.new\""))
        assertEquals("'a'\\''b'", MacDaemon.q("a'b"))
    }

    @Test
    fun `uninstall stops the daemon and removes its copy, plist and socket`() {
        val lines = MacDaemon.uninstallScript().lines()
        assertEquals("/bin/launchctl bootout \"system/\$label\" 2>/dev/null || true", lines[1])
        assertTrue(lines.contains("/bin/rm -f '/Library/LaunchDaemons/com.mythaia.desktop.service.plist'"))
        assertTrue(lines.contains("/bin/rm -rf '/Library/Application Support/Mythaia/Service'"))
        assertTrue(lines.contains("/bin/rm -rf '/var/run/mythaia'"))
        assertFalse("the daemon's log is kept", lines.any { it.contains("rm -rf '/Library/Application Support/Mythaia'") })
    }

    @Test
    fun `the script reaches osascript as one AppleScript string`() {
        val apple = MacDaemon.appleScript("echo \"a\\b\"\nprintf '%s' 'x'", "Mythaia \"Pro\"")
        assertEquals(
            "do shell script \"echo \\\"a\\\\b\\\"\\nprintf '%s' 'x'\" with prompt \"Mythaia \\\"Pro\\\"\" with administrator privileges",
            apple
        )
        assertFalse(apple.contains("\n"))
    }

    @Test
    fun `the scripts are valid sh where there is one to ask`() {
        val sh = File("/bin/sh")
        org.junit.Assume.assumeTrue("no /bin/sh here", sh.canExecute())
        for (script in listOf(MacDaemon.installScript("/Applications/Mythaia Pro.app", "Mythaia Pro"), MacDaemon.uninstallScript())) {
            val process = ProcessBuilder(sh.path, "-n", "-c", script).redirectErrorStream(true).start()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS))
            assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        }
    }
}
