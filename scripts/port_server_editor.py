"""Regenerates desktop ServerEditor.kt from the Android ProxyEditorScreen.kt.

Usage: python scripts/port_server_editor.py app/src/main/java/com/mythaia/ui/proxy/ProxyEditorScreen.kt desktop/src/main/kotlin/com/mythaia/desktop/ui/ServerEditor.kt
Then restore the desktop-only padding (20dp sides, 18dp between sections). New tr() keys go into desktop Strings.kt."""
import re, sys

RENAMES = ["FieldShape", "CardShape", "EDITABLE_PROTOCOLS", "WingField", "UuidField", "SectionCard",
           "SwitchRow", "DropdownField", "FingerprintDropdown"]


def port(src: str) -> str:
    s = src.replace("package com.mythaia.ui.proxy", "package com.mythaia.desktop.ui", 1)
    drop = {"import androidx.compose.ui.res.stringResource", "import com.mythaia.R",
            "import com.mythaia.ui.components.WingSectionTitle", "import com.mythaia.ui.components.wingTextFieldColors"}
    lines = [l for l in s.split("\n") if l.strip() not in drop]
    s = "\n".join(lines)
    # tr import after the last import
    idx = s.rfind("\nimport ")
    end = s.index("\n", idx + 1)
    s = s[:end] + "\nimport com.mythaia.desktop.tr" + s[end:]
    s = re.sub(r"stringResource\(R\.string\.([a-z0-9_]+)\)", r'tr("\1")', s)
    s = re.sub(r"stringResource\(R\.string\.([a-z0-9_]+),\s*", r'tr("\1", ', s)
    s = re.sub(r"stringResource\(if \(([^)]*)\) R\.string\.([a-z0-9_]+) else R\.string\.([a-z0-9_]+)\)",
               r'tr(if (\1) "\2" else "\3")', s)
    for name in RENAMES:
        s = re.sub(r"(?<![A-Za-z0-9_.])" + name + r"\b", "Editor" + name, s)
    # The public editor wraps the form in WithSafeClipboard (Components.kt):
    # AWT throws when another program holds the clipboard, and a text field's
    # paste or copy then closed the window.
    head = ("@OptIn(ExperimentalMaterial3Api::class)\n@Composable\nfun ProxyEditorScreen(\n"
            "    configuration: ProxyConfiguration?,\n    onSave: (ProxyConfiguration) -> Unit,\n"
            "    onDismiss: () -> Unit,\n    /** For a new server: the protocol picked on [ProtocolPickerScreen]. */\n"
            "    initialProtocol: OutboundProtocol? = null\n) {")
    assert head in s, "ProxyEditorScreen's signature changed; update the wrapper in port_server_editor.py"
    s = s.replace(head, (
        "@Composable\nfun ServerEditor(\n"
        "    configuration: ProxyConfiguration?,\n    onSave: (ProxyConfiguration) -> Unit,\n"
        "    onDismiss: () -> Unit,\n    /** For a new server: the protocol picked on the protocol picker. */\n"
        "    initialProtocol: OutboundProtocol? = null\n"
        ") = WithSafeClipboard { ServerEditorForm(configuration, onSave, onDismiss, initialProtocol) }\n\n"
        "@OptIn(ExperimentalMaterial3Api::class)\n@Composable\nprivate fun ServerEditorForm(\n"
        "    configuration: ProxyConfiguration?,\n    onSave: (ProxyConfiguration) -> Unit,\n"
        "    onDismiss: () -> Unit,\n    initialProtocol: OutboundProtocol?\n) {"))
    s = re.sub(r"^internal (fun|val) Editor", r"private \1 Editor", s, flags=re.M)
    s = s.replace("[ProtocolPickerScreen]", "the protocol picker")
    assert "R.string" not in s, [l for l in s.split("\n") if "R.string" in l][:5]
    return s


if __name__ == "__main__":
    out = port(open(sys.argv[1], encoding="utf-8").read())
    open(sys.argv[2], "w", encoding="utf-8").write(out)
