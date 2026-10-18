"""Regenerates desktop ServerEditor.kt from the Android ProxyEditorScreen.kt.

Usage: python scripts/port_server_editor.py app/src/main/java/com/mythaia/ui/proxy/ProxyEditorScreen.kt desktop/src/main/kotlin/com/mythaia/desktop/ui/ServerEditor.kt
The desktop-only differences (padding, plain remember, the insecure switch's label) are applied here,
so the output needs no hand edits. New tr() keys go into desktop Strings.kt."""
import re, sys

RENAMES = ["FieldShape", "CardShape", "EDITABLE_PROTOCOLS", "WingField", "UuidField", "SectionCard",
           "SwitchRow", "DropdownField", "FingerprintDropdown", "InsecureSwitch"]


def port(src: str) -> str:
    s = src.replace("package com.mythaia.ui.proxy", "package com.mythaia.desktop.ui", 1)
    drop = {"import androidx.compose.ui.res.stringResource", "import com.mythaia.R",
            "import com.mythaia.ui.components.WingSectionTitle", "import com.mythaia.ui.components.wingTextFieldColors",
            "import androidx.compose.runtime.saveable.rememberSaveable",
            "// Saveable, so a rotation or a theme switch mid-edit keeps what was typed."}
    lines = [l for l in s.split("\n") if l.strip() not in drop]
    s = "\n".join(lines)
    # A window has no rotation to survive, and the desktop form keeps plain remember.
    s = re.sub(r"\brememberSaveable\b", "remember", s)
    # tr import after java.util.UUID, else after the last import
    anchor = "\nimport java.util.UUID"
    if anchor in s:
        end = s.index(anchor) + len(anchor)
    else:
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
    # The desktop window is wider: more room at the sides, a little less between sections.
    s = s.replace(".padding(horizontal = 16.dp, vertical = 12.dp),\n            verticalArrangement = Arrangement.spacedBy(20.dp)",
                  ".padding(horizontal = 20.dp, vertical = 12.dp),\n            verticalArrangement = Arrangement.spacedBy(18.dp)")
    # Desktop says which server is insecure in the switch's own label.
    s = s.replace('tr("allow_insecure")', 'tr("allow_insecure_server")')
    assert "R.string" not in s, [l for l in s.split("\n") if "R.string" in l][:5]
    return s


if __name__ == "__main__":
    out = port(open(sys.argv[1], encoding="utf-8").read())
    open(sys.argv[2], "w", encoding="utf-8").write(out)
