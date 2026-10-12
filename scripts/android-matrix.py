"""Runs ProtocolMatrixTest on a device or emulator and prints the table.

    python scripts/android-matrix.py <input files...>

Every input is a subscription body (links, base64, Xray/sing-box JSON, Clash)
or a WireGuard .conf, optionally with header lines (#http, #udp, #insecure,
#only, #naive11 — see ProtocolProbe.readInput). Needs the debug app and its
test APK installed:

    ./gradlew :app:installDebug :app:installDebugAndroidTest

adb is taken from $ADB, else $ANDROID_HOME/platform-tools, else PATH; the
device from $ANDROID_SERIAL when several are attached. Results also land in
matrix-results.tsv in the current directory.
"""
import os, shutil, subprocess, sys

DIR = "files/matrix"


def find_adb():
    if os.environ.get("ADB"):
        return os.environ["ADB"]
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if root:
            exe = os.path.join(root, "platform-tools", "adb.exe" if os.name == "nt" else "adb")
            if os.path.exists(exe):
                return exe
    return shutil.which("adb") or "adb"


ADB = [find_adb()] + (["-s", os.environ["ANDROID_SERIAL"]] if os.environ.get("ANDROID_SERIAL") else [])


def adb(*args, check=False):
    r = subprocess.run([*ADB, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        print(r.stdout, r.stderr)
        sys.exit(1)
    return r.stdout + r.stderr


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.stdout.reconfigure(encoding="utf-8")
    adb("shell", f"run-as com.mythaia sh -c 'mkdir -p {DIR} && rm -f {DIR}/*'")
    for f in sys.argv[1:]:
        with open(f, "rb") as data:
            subprocess.run([*ADB, "exec-in", "run-as", "com.mythaia", "sh", "-c",
                            f"cat > {DIR}/{os.path.basename(f)}"], stdin=data, check=True)
    out = adb("shell", "am", "instrument", "-w", "-e", "class", "com.mythaia.vpn.ProtocolMatrixTest",
              "com.mythaia.test/androidx.test.runner.AndroidJUnitRunner")
    print(out.strip()[-300:])
    res = adb("exec-out", "run-as", "com.mythaia", "cat", f"{DIR}/results.tsv")
    open("matrix-results.tsv", "w", encoding="utf-8").write(res)
    ok = 0
    rows = [line.split("\t") for line in res.splitlines()[1:] if line.count("\t") >= 5]
    for c in rows:
        good = all(x.startswith("OK") or x in ("-", "n/a") for x in c[3:6])
        ok += good
        print(("PASS " if good else "FAIL ") + f"{c[1][:32]:32} | {c[2][:26]:26} | {c[3][:44]:44} | {c[4][:30]:30} | {c[5][:44]}")
    print(f"{ok} of {len(rows)} fully passing")


if __name__ == "__main__":
    main()
