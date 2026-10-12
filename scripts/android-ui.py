"""A tiny adb UI driver for checking the app by hand from a terminal.

    python scripts/android-ui.py dump               list visible elements with their centres
    python scripts/android-ui.py tap "Connect"      tap the element with this text (or description)
    python scripts/android-ui.py tapdesc "Add"      tap by content description first
    python scripts/android-ui.py xy 540 900         tap a point
    python scripts/android-ui.py text "hello"       type into the focused field
    python scripts/android-ui.py key 4              send a key event (4 = Back)
    python scripts/android-ui.py shot screen.png    save a screenshot

adb and the device are found as in android-matrix.py ($ADB, $ANDROID_HOME, $ANDROID_SERIAL).
"""
import importlib.util, os, re, subprocess, sys
import xml.etree.ElementTree as ET

_spec = importlib.util.spec_from_file_location("matrix", os.path.join(os.path.dirname(__file__), "android-matrix.py"))
_matrix = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_matrix)
ADB = _matrix.ADB


def adb(*args, binary=False):
    out = subprocess.run([*ADB, *args], capture_output=True)
    return out.stdout if binary else out.stdout.decode("utf-8", "replace")


def dump():
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
    xml = adb("shell", "cat", "/sdcard/ui.xml")
    return ET.fromstring(xml[xml.find("<?xml"):])


def nodes(root):
    for n in root.iter("node"):
        x1, y1, x2, y2 = map(int, re.findall(r"\d+", n.get("bounds", "[0,0][0,0]")))
        yield n, ((x1 + x2) // 2, (y1 + y2) // 2)


def find(root, needle, attr):
    exact = partial = None
    for n, c in nodes(root):
        v = n.get(attr, "")
        if v == needle and exact is None:
            exact = c
        elif needle.lower() in v.lower() and partial is None:
            partial = c
    return exact or partial


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "dump":
        for n, (x, y) in nodes(dump()):
            t, d = n.get("text", ""), n.get("content-desc", "")
            if t or d or n.get("clickable") == "true":
                print(f"{'C' if n.get('clickable') == 'true' else ' '} ({x:4},{y:4}) text={t!r} desc={d!r}")
    elif cmd in ("tap", "tapdesc"):
        root = dump()
        first, second = ("text", "content-desc") if cmd == "tap" else ("content-desc", "text")
        c = find(root, sys.argv[2], first) or find(root, sys.argv[2], second)
        if not c:
            sys.exit(f"not found: {sys.argv[2]}")
        adb("shell", "input", "tap", str(c[0]), str(c[1]))
    elif cmd == "xy":
        adb("shell", "input", "tap", sys.argv[2], sys.argv[3])
    elif cmd == "text":
        adb("shell", "input", "text", sys.argv[2].replace(" ", "%s"))
    elif cmd == "key":
        adb("shell", "input", "keyevent", sys.argv[2])
    elif cmd == "shot":
        open(sys.argv[2], "wb").write(adb("exec-out", "screencap", "-p", binary=True))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
